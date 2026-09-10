#!/usr/bin/env python3
"""Splunk HEC JSON ingestion using only the Python standard library."""
import argparse
import decimal
import errno
import collections
import fcntl
import gzip
import hmac
import io
import json
import logging
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import sys
import uuid
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class HECError(Exception):
    def __init__(self, status, code, text):
        self.status, self.code, self.text = status, code, text


def invalid(*_):
    raise ValueError("Invalid JSON constant")


class Audit:
    """Bounded log volume with fixed-cardinality counters; never log input data."""
    def __init__(self, rate=10, burst=20):
        self.lock = threading.Lock()
        self.rate, self.burst = rate, burst
        self.tokens, self.updated = float(burst), time.monotonic()
        self.counters = collections.Counter()
        self.suppressed = 0

    def record(self, outcome, peer="", endpoint="unknown", status=0, request_id=""):
        with self.lock:
            self.counters[outcome] += 1
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens < 1:
                self.suppressed += 1
                return
            self.tokens -= 1
            record = dict(event=outcome, peer=peer, endpoint=endpoint,
                          status=status, request_id=request_id, suppressed=self.suppressed)
            self.suppressed = 0
        logging.log(logging.ERROR if outcome == "storage_error" else logging.WARNING,
                    "%s", json.dumps(record))

    def summary(self):
        with self.lock:
            if not self.counters:
                return
            record = dict(event="security_summary", counts=dict(self.counters),
                          suppressed=self.suppressed)
            self.counters.clear()
            self.suppressed = 0
        logging.warning("%s", json.dumps(record))


class Connections:
    """Shared admission and absolute deadlines across HTTP and HTTPS listeners."""
    def __init__(self, maximum=32, header_timeout=5, request_timeout=30):
        self.maximum = maximum
        self.header_timeout, self.request_timeout = header_timeout, request_timeout
        self.condition = threading.Condition()
        self.active = {}
        self.stopped = False
        self.audit = Audit()
        self.monitor = threading.Thread(target=self.watch, daemon=True)
        self.monitor.start()

    def admit(self, request, peer):
        with self.condition:
            if self.stopped or len(self.active) >= self.maximum:
                self.audit.record("connection_limit", peer)
                return False
            now = time.monotonic()
            self.active[request] = [request, now + self.request_timeout,
                                    now + min(self.header_timeout, self.request_timeout), peer]
            self.condition.notify_all()
            return True

    def replace(self, request, secured):
        with self.condition:
            self.active[request][0] = secured

    def body(self, request):
        with self.condition:
            item = self.active.get(request)
            if item:
                item[2] = item[1]
                self.condition.notify_all()

    def release(self, request):
        with self.condition:
            self.active.pop(request, None)
            self.condition.notify_all()

    @staticmethod
    def disconnect(request):
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def watch(self):
        next_summary = time.monotonic() + 30
        with self.condition:
            while not self.stopped:
                now = time.monotonic()
                if now >= next_summary:
                    self.audit.summary()
                    next_summary = now + 30
                for item in self.active.values():
                    if item[2] <= now:
                        self.disconnect(item[0])
                        self.audit.record("request_timeout", item[3])
                        item[2] = float("inf")
                self.condition.wait(0.05)

    def close(self, grace=0):
        with self.condition:
            deadline = time.monotonic() + grace
            while self.active and time.monotonic() < deadline:
                self.condition.wait(max(0, deadline - time.monotonic()))
            self.stopped = True
            for item in self.active.values():
                self.disconnect(item[0])
            self.condition.notify_all()
        self.monitor.join()
        self.audit.summary()


def number(value):
    # Bound both numeric parsing work and exponent range, preserving original text.
    if len(value) > 1024:
        raise ValueError("Numeric literal too long")
    result = decimal.Decimal(value)
    if not result.is_finite() or abs(result.as_tuple().exponent) > 10000:
        raise ValueError("Numeric exponent out of range")
    return result


class Collector:
    def __init__(self, directory, token="", max_bytes=10 << 20, *,
                 max_expanded_bytes=10 << 20, max_events=10000,
                 max_query_bytes=8192, max_metadata_bytes=1024,
                 max_storage_bytes=10 << 30, max_files=100000,
                 min_free_bytes=256 << 20, min_free_inodes=1024,
                 requests_per_second=100):
        self.directory = Path(directory).resolve()
        self.token, self.max_bytes = token, max_bytes
        self.max_expanded_bytes, self.max_events = max_expanded_bytes, max_events
        self.max_query_bytes, self.max_metadata_bytes = max_query_bytes, max_metadata_bytes
        self.max_storage_bytes, self.max_files = max_storage_bytes, max_files
        self.min_free_bytes, self.min_free_inodes = min_free_bytes, min_free_inodes
        self.lock = threading.Lock()
        self.audit = Audit()
        self.requests_per_second = requests_per_second
        self.tokens, self.updated = float(requests_per_second), time.monotonic()
        self.directory_lock = None

    def prepare(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError("events directory must be owned by this user and not group/world writable")
        # One writer process per directory makes quota checks and writes atomic together.
        fd = os.open(self.directory / ".hec.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.directory_lock = os.fdopen(fd, "a")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.directory_lock.close()
            self.directory_lock = None
            raise ValueError("events directory is already in use") from None

    def close(self):
        if self.directory_lock:
            self.directory_lock.close()
            self.directory_lock = None

    def throttle(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.requests_per_second,
                              self.tokens + (now - self.updated) * self.requests_per_second)
            self.updated = now
            if self.tokens < 1:
                raise HECError(503, 9, "Server is busy")
            self.tokens -= 1

    def capacity(self, size=0):
        used = count = 0
        # Include orphan temporary files. Re-scan to recognize operator retention.
        with os.scandir(self.directory) as entries:
            for entry in entries:
                if entry.name == ".hec.lock":
                    continue
                info = entry.stat(follow_symlinks=False)
                count += 1
                used += info.st_size
        disk = os.statvfs(self.directory)
        if (used + size > self.max_storage_bytes or count >= self.max_files or
                disk.f_bavail * disk.f_frsize - size < self.min_free_bytes or
                (disk.f_files and disk.f_favail < self.min_free_inodes + 1)):
            raise HECError(503, 9, "Storage capacity exhausted")

    def ready(self):
        with self.lock:
            self.capacity(1)
            with tempfile.TemporaryFile(dir=self.directory):
                pass

    def ingest(self, data, query):
        try:
            if len(data) > self.max_bytes:
                raise HECError(413, 6, "Request too large")
            for key in ("host", "source", "sourcetype", "index", "time"):
                if key in query and len(query[key][0].encode("utf-8")) > self.max_metadata_bytes:
                    raise HECError(413, 6, "Metadata too large")
            text = data.decode("utf-8")
            decoder = json.JSONDecoder(parse_float=number, parse_int=number, parse_constant=invalid)
            events, size = [], 5  # Opening and closing JSON array delimiters.
            pos = 0
            while pos < len(text):
                while pos < len(text) and text[pos] in " \t\r\n":
                    pos += 1
                if pos == len(text):
                    break
                if len(events) >= self.max_events:
                    raise HECError(413, 6, "Too many events")
                event, end = decoder.raw_decode(text, pos)
                if not isinstance(event, dict):
                    raise ValueError("Expected event envelope")
                if "event" not in event:
                    raise HECError(400, 12, "Event field is required")
                value = event["event"]
                if value is None or value == "" or value == {}:
                    raise HECError(400, 13, "Event field cannot be blank")
                if not isinstance(value, (str, dict)):
                    raise ValueError("Expected string or object event")
                defaults = {key: query[key][0] for key in
                            ("host", "source", "sourcetype", "index", "time")
                            if key not in event and key in query}
                raw = text[pos:end]
                if defaults:
                    raw = raw[:-1] + "," + json.dumps(defaults)[1:]
                raw = raw.encode("utf-8")
                size += len(raw) + (2 if events else 0)
                if size > self.max_expanded_bytes:
                    raise HECError(413, 6, "Expanded batch too large")
                events.append(raw)
                pos = end
        except (ValueError, UnicodeError, RecursionError, decimal.DecimalException) as exc:
            raise HECError(400, 6, "Invalid data format") from exc
        if not events:
            raise HECError(400, 5, "No data")
        self.store(events, size)

    def store(self, events, size):
        # Serialize capacity checks and publication across all request workers.
        with self.lock:
            self.capacity(size)
            name = None
            try:
                with tempfile.NamedTemporaryFile(mode="wb", dir=self.directory,
                                                 prefix=".pending-", delete=False) as output:
                    name = Path(output.name)
                    output.write(b"[\n")
                    for index, event in enumerate(events):
                        if index:
                            output.write(b",\n")
                        output.write(event)
                    output.write(b"\n]\n")
                    output.flush()
                    os.fsync(output.fileno())
                target = self.directory / ("events-" + uuid.uuid4().hex + ".json")
                os.link(name, target)
            finally:
                if name is not None:
                    name.unlink(missing_ok=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HEC"
    sys_version = ""

    def handle(self):
        # Includes response writes from except blocks and parser-generated errors.
        try:
            super().handle()
        except (OSError, TimeoutError):
            self.close_connection = True
            self.server.collector.audit.record("client_disconnect", self.client_address[0])

    def parse_request(self):
        result = super().parse_request()
        if result:
            self.server.connections.body(self.server.request_keys.get(self.request, self.request))
        return result


    def setup(self):
        self.request_id = uuid.uuid4().hex
        self.endpoint = "unknown"
        self.request.settimeout(self.server.connections.request_timeout)
        super().setup()

    def respond(self, status, code, text, allow=None):
        if status >= 400:
            outcome = ("auth_failure" if status in (401, 403) else
                       "storage_error" if status == 500 else
                       "capacity_rejection" if status == 503 else "request_rejected")
            self.server.collector.audit.record(outcome, self.client_address[0], self.endpoint,
                                               status, self.request_id)
        body = json.dumps({"text": text, "code": code}).encode() + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Close after each response, including errors with unread request bodies.
        self.send_header("Connection", "close")
        if status == 503:
            self.send_header("Retry-After", "1")
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def read_exact(self, size):
        data = self.rfile.read(size)
        if len(data) != size:
            raise HECError(400, 6, "Invalid data format")
        return data

    def read_body(self):
        limit = self.server.collector.max_bytes
        lengths = self.headers.get_all("Content-Length", [])
        transfers = self.headers.get_all("Transfer-Encoding", [])
        if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers):
            raise HECError(400, 6, "Invalid data format")
        if transfers:
            if transfers[0].lower().strip() != "chunked":
                raise HECError(400, 6, "Invalid data format")
            data = bytearray()
            while True:
                line = self.rfile.readline(8193)
                number = line.split(b";", 1)[0].strip()
                if len(line) > 8192 or not line.endswith(b"\r\n") or not number or any(
                        c not in b"0123456789abcdefABCDEF" for c in number):
                    raise HECError(400, 6, "Invalid data format")
                size = int(number, 16)
                if len(data) + size > limit:
                    raise HECError(413, 6, "Request too large")
                if size == 0:
                    trailer_bytes = 0
                    while True:
                        trailer = self.rfile.readline(8193)
                        trailer_bytes += len(trailer)
                        if not trailer.endswith(b"\r\n") or trailer_bytes > 65536:
                            raise HECError(400, 6, "Invalid data format")
                        if trailer == b"\r\n":
                            break
                    break
                data.extend(self.read_exact(size))
                if self.read_exact(2) != b"\r\n":
                    raise HECError(400, 6, "Invalid data format")
            data = bytes(data)
        else:
            value = lengths[0] if lengths else "0"
            if not value.isascii() or not value.isdigit():
                raise HECError(400, 6, "Invalid data format")
            try:
                size = int(value)
            except ValueError as exc:
                raise HECError(400, 6, "Invalid data format") from exc
            if size > limit:
                raise HECError(413, 6, "Request too large")
            data = self.read_exact(size)
        encoding = self.headers.get("Content-Encoding", "").strip().lower()
        if encoding == "gzip":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
                    data = zipped.read(limit + 1)
            except (OSError, EOFError, zlib.error) as exc:
                raise HECError(400, 6, "Invalid data format") from exc
        elif encoding not in ("", "identity"):
            raise HECError(415, 6, "Unsupported content encoding")
        if len(data) > limit:
            raise HECError(413, 6, "Request too large")
        return data

    def dispatch(self):
        try:
            url = urlsplit(self.path)
            path = url.path.removesuffix("/")
            known = {"/services/collector", "/services/collector/event",
                     "/services/collector/event/1.0", "/services/collector/ack",
                     "/services/collector/health", "/services/collector/health/1.0",
                     "/services/collector/ready"}
            self.endpoint = path if path in known else "unknown"
            if len(url.query.encode("utf-8")) > self.server.collector.max_query_bytes:
                raise HECError(413, 6, "Query too large")
            if path == "/services/collector/ready":
                self.server.collector.throttle()
                if self.command != "GET":
                    self.respond(405, 6, "Method not allowed", "GET")
                else:
                    self.server.collector.ready()
                    self.respond(200, 17, "HEC is ready")
                return
            if path in ("/services/collector/health", "/services/collector/health/1.0"):
                if self.command != "GET":
                    self.respond(405, 6, "Method not allowed", "GET")
                else:
                    self.respond(200, 17, "HEC is healthy")
                return
            if path not in ("/services/collector", "/services/collector/event",
                            "/services/collector/event/1.0", "/services/collector/ack"):
                raise HECError(404, 6, "Not found")
            if self.command != "POST":
                self.respond(405, 6, "Method not allowed", "POST")
                return
            collector = self.server.collector
            collector.throttle()
            if collector.token:
                auth = self.headers.get("Authorization", "")
                if not auth:
                    raise HECError(401, 2, "Token is required")
                parts = auth.split()
                if len(parts) != 2 or parts[0].lower() != "splunk":
                    raise HECError(401, 3, "Invalid authorization")
                if not hmac.compare_digest(parts[1].encode(), collector.token.encode()):
                    raise HECError(403, 4, "Invalid token")
            if path == "/services/collector/ack":
                raise HECError(400, 14, "ACK is disabled")
            collector.ingest(self.read_body(), parse_qs(url.query, keep_blank_values=True,
                                                       max_num_fields=32))
            self.respond(200, 0, "Success")
        except HECError as exc:
            self.respond(exc.status, exc.code, exc.text)
        except (TimeoutError, ConnectionError):
            self.close_connection = True
        except OSError as exc:
            if exc.errno in (errno.ENOSPC, errno.EDQUOT) or self.endpoint == "/services/collector/ready":
                self.respond(503, 9, "Storage unavailable")
            else:
                self.respond(500, 8, "Internal server error")
        except ValueError:
            self.respond(400, 6, "Invalid data format")

    do_POST = do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = dispatch

    def send_error(self, code, message=None, explain=None):
        self.respond(code, 6, "Invalid HTTP request")

    def log_message(self, format, *args):
        # Do not log request URLs or headers which can contain credentials.
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, collector, tls_context=None, connections=None):
        self.collector = collector
        self.tls_context = tls_context
        self.connections = connections or Connections()
        self.connections.audit = collector.audit
        self.owns_connections = connections is None
        self.request_keys = {}
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        try:
            super().__init__(address, Handler)
        except BaseException:
            if self.owns_connections:
                self.connections.close()
            raise

    def server_bind(self):
        # A listener does not need reverse DNS; avoid blocking startup on a resolver.
        socketserver.TCPServer.server_bind(self)
        self.server_name = socket.gethostname()
        self.server_port = self.server_address[1]

    def process_request(self, request, client_address):
        # Refuse overload before spawning a worker or starting a TLS handshake.
        if not self.connections.admit(request, client_address[0]):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except RuntimeError:
            self.connections.release(request)
            self.shutdown_request(request)
            self.connections.audit.record("worker_unavailable", client_address[0])
        except BaseException:
            self.connections.release(request)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release(request)

    def finish_request(self, request, client_address):
        request.settimeout(self.connections.header_timeout)
        if self.tls_context:
            try:
                # Hold deadline lock while changing socket ownership to avoid a race.
                with self.connections.condition:
                    secured = self.tls_context.wrap_socket(request, server_side=True,
                                                           do_handshake_on_connect=False)
                    self.connections.replace(request, secured)
                with secured:
                    self.request_keys[secured] = request
                    try:
                        secured.do_handshake()
                        super().finish_request(secured, client_address)
                    finally:
                        self.request_keys.pop(secured, None)
            except OSError:
                self.connections.audit.record("tls_failure", client_address[0])
        else:
            super().finish_request(request, client_address)

    def server_close(self):
        super().server_close()
        if self.owns_connections:
            self.connections.close()


def address(value):
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise ValueError("listen address must be host:port, :port, or [IPv6]:port")
    return host.strip("[]"), int(port)


def main():
    if sys.version_info < (3, 12):
        raise SystemExit("hec: Python 3.12 or newer is required; use a supported patched runtime")
    parser = argparse.ArgumentParser(description=__doc__)
    for name, default in (("http-addr", "127.0.0.1:8088"), ("https-addr", ""),
                          ("tls-cert", ""), ("tls-key", ""),
                          ("events-dir", "./events"), ("token", os.getenv("HEC_TOKEN", ""))):
        parser.add_argument("-" + name, "--" + name, default=default)
    parser.add_argument("-no-auth", "--no-auth", action="store_true")
    parser.add_argument("-max-body-bytes", "--max-body-bytes", type=int, default=10 << 20)
    limits = {"max-connections": 32, "header-timeout": 5, "request-timeout": 30,
              "max-expanded-bytes": 10 << 20, "max-events": 10000,
              "max-query-bytes": 8192, "max-metadata-bytes": 1024,
              "max-storage-bytes": 10 << 30, "max-files": 100000,
              "min-free-bytes": 256 << 20, "min-free-inodes": 1024,
              "requests-per-second": 100}
    for name, default in limits.items():
        parser.add_argument("-" + name, "--" + name, type=int, default=default)
    args = parser.parse_args()
    for name in limits:
        if not 0 < getattr(args, name.replace("-", "_")) < (1 << 63) - 1:
            parser.error(name + " must be positive and less than MaxInt64")
    if not args.http_addr and not args.https_addr:
        parser.error("enable at least one HTTP or HTTPS listener")
    if not 0 < args.max_body_bytes < (1 << 63) - 1:
        parser.error("max-body-bytes must be positive and less than MaxInt64")
    if not args.token and not args.no_auth:
        parser.error("set HEC_TOKEN, -token, or explicitly use -no-auth")
    if args.token and args.no_auth:
        parser.error("-no-auth and a configured token are mutually exclusive")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    servers, threads = [], []
    connections = collector = None
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        tls_context = None
        if args.https_addr:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_context.load_cert_chain(args.tls_cert, args.tls_key)
        config = {name.replace("-", "_"): getattr(args, name.replace("-", "_"))
                  for name in limits if name not in ("max-connections", "header-timeout", "request-timeout")}
        collector = Collector(args.events_dir, args.token, args.max_body_bytes, **config)
        collector.prepare()
        connections = Connections(args.max_connections, args.header_timeout, args.request_timeout)
        logging.info("runtime: Python %s; %s", sys.version.split()[0], ssl.OPENSSL_VERSION)
        for endpoint, context in ((args.http_addr, None), (args.https_addr, tls_context)):
            if endpoint:
                server = Server(address(endpoint), collector, context, connections)
                servers.append(server)
                logging.info("listening on %s (TLS=%s), events directory: %s",
                             server.server_address, context is not None, collector.directory)
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        stopped.wait()
    except (OSError, ValueError) as exc:
        parser.exit(1, f"hec: {exc}\n")
    finally:
        for server in servers[:len(threads)]:
            server.shutdown()
        for server in servers:
            server.server_close()
        if connections:
            connections.close(grace=10)
        if collector:
            collector.close()


if __name__ == "__main__":
    main()
