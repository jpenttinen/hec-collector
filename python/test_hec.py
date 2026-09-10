import concurrent.futures
import gzip
import http.client
import json
import logging
import socket
import time
import io
import errno
import os
import queue
import re
import sys
from types import SimpleNamespace
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from hec import Audit, Collector, Connections, Handler, HECError, Server


class HECTest(unittest.TestCase):
    def setUp(self):
        # Capture security logs without flooding the test runner output.
        self.log_capture = io.StringIO()
        handler = logging.StreamHandler(self.log_capture)
        root = logging.getLogger()
        old_handlers = root.handlers[:]
        root.handlers[:] = [handler]
        self.addCleanup(lambda: setattr(root, "handlers", old_handlers))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.collector = Collector(self.directory, "secret", 1024)
        self.server = self.start_server()

    def start_server(self, context=None, connections=None):
        server = Server(("127.0.0.1", 0), self.collector, context, connections)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        def close():
            server.shutdown()
            server.server_close()
            worker.join()
        self.addCleanup(close)
        return server

    def request(self, body=b'{"event":"hello"}', path="/services/collector/event",
                auth="Splunk secret", method="POST", headers=None, server=None, context=None,
                chunked=False):
        server = server or self.server
        if context:
            conn = http.client.HTTPSConnection(*server.server_address, context=context, timeout=5)
        else:
            conn = http.client.HTTPConnection(*server.server_address, timeout=5)
        try:
            hdr = dict(headers or {})
            if auth is not None:
                hdr["Authorization"] = auth
            conn.request(method, path, body, hdr, encode_chunked=chunked)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_errors_do_not_write(self):
        for body, auth, status, code in [
            (b'{}', 'Splunk secret', 400, 12),
            (b'{"event":null}', 'Splunk secret', 400, 13),
            (b'{"event":""}', 'Splunk secret', 400, 13),
            (b'{"event":1}', 'Splunk secret', 400, 6),
            (b'[{"event":"x"}]', 'Splunk secret', 400, 6),
            (b'{"event":"x"}{', 'Splunk secret', 400, 6),
            (b'{"event":{"n":NaN}}', 'Splunk secret', 400, 6),
            (b'', 'Splunk secret', 400, 5),
            (b'{}', None, 401, 2),
            (b'{}', 'Bearer secret', 401, 3),
            (b'{}', 'Splunk wrong', 403, 4),
        ]:
            with self.subTest(body=body, auth=auth):
                result = self.request(body, auth=auth)
                self.assertEqual((result[0], result[1]['code']), (status, code))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_batch_precision_and_defaults(self):
        payload = b'{"event":{"n":9007199254740993,"f":0.1234567890123456789},"host":"override"}\n{"event":"two"}'
        self.assertEqual(self.request(payload, path='/services/collector/?host=default&source=test')[0], 200)
        files = list(self.directory.glob('events-*.json'))
        self.assertEqual(len(files), 1)
        text = files[0].read_text()
        self.assertIn('0.1234567890123456789', text)
        events = json.loads(text)
        self.assertEqual(events[0]['event']['n'], 9007199254740993)
        self.assertEqual(events[0]['host'], 'override')
        self.assertEqual(events[1]['host'], 'default')
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.directory.glob('.pending-*')))

    def test_gzip_and_limits(self):
        self.assertEqual(self.request(gzip.compress(b'{"event":"ok"}'), headers={'Content-Encoding':'gzip'})[0], 200)
        large = b'{"event":"' + b'a' * 2000 + b'"}'
        for body, headers in [(large, {}), (gzip.compress(large), {'Content-Encoding':'gzip'}),
                              (b'invalid', {'Content-Encoding':'gzip'})]:
            status = self.request(body, headers=headers)[0]
            self.assertEqual(status, 400 if body == b'invalid' else 413)
        self.assertEqual(len(list(self.directory.glob('*.json'))), 1)

    def test_corrupt_deflate(self):
        broken = bytes.fromhex("1f8b0800000000000003") + b"\xff" * 20
        self.assertEqual(self.request(broken, headers={"Content-Encoding": "gzip"})[0], 400)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_chunked(self):
        self.assertEqual(self.request(iter([b'{"event":', b'"chunked"}']), chunked=True)[0], 200)
        self.assertEqual(self.request(iter([b'a' * 2000]), chunked=True)[0], 413)

    def test_routes(self):
        for path, method, status in [('/services/collector/health', 'GET', 200),
                                     ('/services/collector/health/1.0', 'GET', 200),
                                     ('/services/collector/event/1.0', 'POST', 200),
                                     ('/services/collector', 'GET', 405),
                                     ('/services/collector/ack', 'POST', 400),
                                     ('/missing', 'POST', 404)]:
            self.assertEqual(self.request(path=path, method=method)[0], status)

    def test_concurrent(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.request()[0], range(30)))
        self.assertEqual(results, [200] * 30)
        self.assertEqual(len(list(self.directory.glob('*.json'))), 30)

    def test_storage_failure(self):
        with patch('hec.os.link', side_effect=OSError('disk failure')), self.assertLogs(level='ERROR'):
            self.assertEqual(self.request()[0], 500)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_https(self):
        cert, key = self.directory / 'cert.pem', self.directory / 'key.pem'
        config = self.directory / 'openssl.cnf'
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\n[v3]\n"
                          "basicConstraints=critical,CA:TRUE\n"
                          "keyUsage=critical,keyCertSign,cRLSign,digitalSignature,keyEncipherment\n"
                          "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        subprocess.run(['openssl', 'req' , '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost', '-config', str(config)], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server = self.start_server(context, connections=self.server.connections)
        client = ssl.create_default_context(cafile=str(cert))
        self.assertEqual(self.request(server=server, context=client)[0], 200)
        self.assertEqual(len(list(self.directory.glob('*.json'))), 1)
        self.wait_for(lambda: not server.connections.active)
        server.connections.header_timeout = .25
        with socket.create_connection(server.server_address, timeout=2):
            self.wait_for(lambda: len(server.connections.active) == 1)
            self.wait_for(lambda: not server.connections.active)
        self.assertEqual(self.request(server=server, context=client)[0], 200)

    def test_expanded_batch_limit(self):
        self.collector.max_expanded_bytes = 1024
        body = b'{"event":"x"}' * 70
        self.assertEqual(self.request(body, path='/services/collector?host=' + 'a' * 100)[0], 413)
        self.assertEqual(list(self.directory.glob('*.json')), [])

    def test_event_and_query_limits(self):
        self.collector.max_events = 1
        self.assertEqual(self.request(b'{"event":"x"}{"event":"y"}')[0], 413)
        self.assertEqual(self.request(path='/services/collector?host=' + 'a' * 1025)[0], 413)
        self.assertEqual(self.request(path='/services/collector?x=' + 'a' * 8193)[0], 413)
        self.assertEqual(self.request(path='/services/collector?' + '&'.join('x=1' for _ in range(33)))[0], 400)
        self.assertEqual(list(self.directory.glob('*.json')), [])

    def test_numeric_errors_are_json_responses(self):
        self.collector.max_bytes = 4096
        for numeric in (b'1e9999999999999999999', b'1e10001', b'9' * 1025):
            self.assertEqual(self.request(b'{"event":{"n":' + numeric + b'}}')[0], 400)
        self.assertEqual(list(self.directory.glob('*.json')), [])
        self.assertNotIn('Traceback', self.log_capture.getvalue())

    def test_concurrent_storage_quota_and_recovery(self):
        self.collector.max_files = 3
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(lambda _: self.request()[0], range(12)))
        self.assertEqual(codes.count(200), 3)
        self.assertEqual(codes.count(503), 9)
        self.assertEqual(self.request(method='GET', path='/services/collector/ready')[0], 503)
        next(self.directory.glob('*.json')).unlink()
        self.assertEqual(self.request(method='GET', path='/services/collector/ready')[0], 200)
        self.assertEqual(self.request()[0], 200)

    def test_byte_quota_accounts_for_serialized_bytes(self):
        body = b'{"event":"hello"}'
        self.collector.max_storage_bytes = len(body) + 5
        self.assertEqual(self.request(body)[0], 200)
        self.assertEqual(next(self.directory.glob('*.json')).stat().st_size,
                         self.collector.max_storage_bytes)
        self.assertEqual(self.request(body)[0], 503)

    def test_free_space_and_inode_reserves(self):
        for free_bytes, free_inodes in ((100, 10000), (1 << 30, 1)):
            disk = SimpleNamespace(f_bavail=free_bytes, f_frsize=1, f_files=10000,
                                   f_favail=free_inodes)
            with patch('hec.os.statvfs', return_value=disk):
                self.assertEqual(self.request()[0], 503)
        self.assertEqual(list(self.directory.glob('*.json')), [])

    def test_disk_full_after_capacity_check(self):
        with patch('hec.os.link', side_effect=OSError(errno.ENOSPC, 'full')):
            self.assertEqual(self.request()[0], 503)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_storage_directory_lock(self):
        self.collector.prepare()
        self.addCleanup(self.collector.close)
        other = Collector(self.directory)
        with self.assertRaisesRegex(ValueError, 'already in use'):
            other.prepare()
        self.collector.close()
        other.prepare()
        other.close()

    def test_rate_limit_includes_invalid_tokens(self):
        self.collector.requests_per_second = 1
        self.collector.tokens = 1
        self.collector.updated = time.monotonic()
        self.assertEqual(self.request(auth='Splunk wrong')[0], 403)
        self.assertEqual(self.request()[0], 503)
        self.assertEqual(list(self.directory.glob('*.json')), [])

    def test_audit_redaction_and_sampling(self):
        self.assertEqual(self.request(auth='Splunk TOPSECRET',
                                     path='/services/collector?host=PRIVATE')[0], 403)
        logs = self.log_capture.getvalue()
        self.assertIn('auth_failure', logs)
        self.assertIn('request_id', logs)
        self.assertNotIn('TOPSECRET', logs)
        self.assertNotIn('PRIVATE', logs)
        audit = Audit(rate=0, burst=2)
        with self.assertLogs(level='WARNING') as captured:
            for _ in range(20):
                audit.record('auth_failure')
            audit.summary()
        self.assertEqual(len(captured.output), 3)
        self.assertIn('"suppressed": 18', captured.output[-1])

    def wait_for(self, predicate):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.01)
        self.fail('condition not reached')

    def test_shared_connection_cap_and_release(self):
        connections = Connections(maximum=1)
        self.addCleanup(connections.close)
        first = self.start_server(connections=connections)
        second = self.start_server(connections=connections)
        held = socket.create_connection(first.server_address, timeout=2)
        self.addCleanup(held.close)
        held.sendall(b'POST /services/collector HTTP/1.1\r\nHost: test\r\n')
        self.wait_for(lambda: len(connections.active) == 1)
        with socket.create_connection(second.server_address, timeout=2) as rejected:
            self.assertEqual(rejected.recv(1), b'')
        self.assertEqual(len(connections.active), 1)
        held.shutdown(socket.SHUT_RDWR)
        held.close()
        self.wait_for(lambda: not connections.active)
        self.assertEqual(self.request(server=second)[0], 200)

    def test_absolute_header_and_body_deadlines(self):
        for stage in ('header', 'body'):
            connections = Connections(header_timeout=.25, request_timeout=.4)
            self.addCleanup(connections.close)
            server = self.start_server(connections=connections)
            with socket.create_connection(server.server_address, timeout=2) as slow:
                if stage == 'header':
                    slow.sendall(b'POST /services/collector HTTP/1.1\r\nX-Slow: ')
                else:
                    slow.sendall(b'POST /services/collector HTTP/1.1\r\nHost: test\r\n'
                                 b'Authorization: Splunk secret\r\nContent-Length: 100\r\n\r\n')
                self.wait_for(lambda: len(connections.active) == 1)
                started = time.monotonic()
                while time.monotonic() - started < .7:
                    try:
                        slow.sendall(b'a')
                    except OSError:
                        break
                    time.sleep(.04)
                self.wait_for(lambda: not connections.active)
                self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(list(self.directory.glob('*.json')), [])

    def test_disconnect_during_error_response_is_contained(self):
        with patch.object(Handler, 'respond', side_effect=BrokenPipeError('client left')):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request(auth='Splunk wrong')
        self.assertIn('client_disconnect', self.log_capture.getvalue())
        self.assertNotIn('Traceback', self.log_capture.getvalue())
        self.assertEqual(self.request()[0], 200)

    def test_unsupported_runtime_is_rejected(self):
        from hec import main
        with patch('hec.sys.version_info', (3, 9, 6)):
            with self.assertRaisesRegex(SystemExit, 'Python 3.12'):
                main()

    def test_cli_startup_storage_and_shutdown(self):
        environment = dict(os.environ)
        environment.pop('HEC_TOKEN', None)
        process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('hec.py')),
                                    '-no-auth', '-http-addr', '127.0.0.1:0',
                                    '-events-dir', str(self.directory / 'cli-events')],
                                   cwd=self.directory, env=environment, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = queue.Queue()
        def read_logs():
            for line in process.stderr:
                lines.put(line)
        reader = threading.Thread(target=read_logs, daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 5
            port = None
            while time.monotonic() < deadline:
                line = lines.get(timeout=max(.01, deadline - time.monotonic()))
                match = re.search(r"listening on \('127\.0\.0\.1', (\d+)\)", line)
                if match:
                    port = int(match[1])
                    break
            self.assertIsNotNone(port)
            endpoint = SimpleNamespace(server_address=('127.0.0.1', port))
            self.assertEqual(self.request(server=endpoint)[0], 200)
            self.assertEqual(len(list((self.directory / 'cli-events').glob('*.json'))), 1)
            process.terminate()
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main()
