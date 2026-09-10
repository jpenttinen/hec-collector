# Python HEC receiver

Standard-library-only Python implementation of Splunk HEC JSON ingestion over HTTP/HTTPS, storing events in local JSON files. Requires a current patched **Python 3.12+** on Linux/macOS; the CLI rejects older runtimes.

Run all commands below from the `python/` directory (`cd python` from the repository root). The Go implementation is independent in [../go](../go/README.md).

## Run

The Python implementation uses only the standard library. It accepts the original Go flags (both `-flag` and `--flag` spellings), plus the security limits below. Run one implementation per port and use separate events directories for independent Go/Python processes.

Use a supported, patched interpreter. On this workstation Python 3.14 is available as `/opt/homebrew/bin/python3.14`; the system `python3` is too old. For example:

```sh
export HEC_TOKEN='replace-with-a-long-random-token'
python3.14 hec.py -events-dir /absolute/path/to/events
```

Python defaults to **HTTP on `127.0.0.1:8088`**, restricting it to local clients. For remote clients, enable HTTPS with a trusted certificate and disable HTTP:

```sh
python3.14 hec.py -http-addr '' -https-addr :8443 \
  -tls-cert server.crt -tls-key server.key -events-dir ./events
```

To deliberately run both protocols, set `-http-addr 127.0.0.1:8088` with `-https-addr :8443`. Use `-http-addr :8088` only for a trusted network or an appropriately restricted proxy backend; HTTP transmits the reusable token and events without encryption. The ingestion example below uses this listener.

## Security limits

| Flag | Default | Behavior |
| --- | --- | --- |
| `-max-connections` | 32 | Combined HTTP/HTTPS worker cap; excess sockets close before a worker or TLS handshake starts |
| `-header-timeout` | 5 seconds | Absolute deadline from accept through TLS handshake and HTTP headers |
| `-request-timeout` | 30 seconds | Absolute socket deadline from accept through the whole request; sending occasional bytes does not extend it |
| `-requests-per-second` | 100 | Shared token bucket for ingestion/ACK attempts and readiness checks, including invalid tokens; burst equals the rate |
| `-max-expanded-bytes` | 10485760 | Serialized JSON array limit after applying query defaults, including delimiters |
| `-max-events` | 10000 | Events per batch |
| `-max-query-bytes` | 8192 | Encoded query-string bytes; at most 32 query fields |
| `-max-metadata-bytes` | 1024 | UTF-8 bytes per query-default value |
| `-max-storage-bytes` | 10737418240 (10 GiB) | Maximum combined logical size of direct entries in the events directory, excluding `.hec.lock` |
| `-max-files` | 100000 | Maximum direct directory entries, excluding `.hec.lock` |
| `-min-free-bytes` | 268435456 (256 MiB) | Filesystem free-space reserve checked before each write |
| `-min-free-inodes` | 1024 | Free-inode reserve on filesystems reporting inode totals |

All limit flags require positive integers. Body limits still apply to compressed and decompressed bodies. Number literals are limited to 1,024 characters and an absolute decimal exponent of 10,000; original accepted numeric text is preserved. A batch exceeding its event/metadata/output limits returns HTTP 413 and publishes no event file.

Storage checks and publication are serialized across workers. A `.hec.lock` advisory lock prevents two Python CLI instances from using the same events directory. Do not delete that lock file while the server is running. The directory must be owned by the service user and must not be group/world writable. Existing permissions are validated, not silently changed. Python requires POSIX file locking, `statvfs`, and hard-link support (Linux/macOS).

Each write scans the flat events directory, including orphan `.pending-*` files, before allocating more space. This recognizes operator-managed retention and existing files on restart, at the cost of more work in large directories. Quota, rate, and storage-reserve failures return HTTP 503 with `Retry-After: 1`. Clients should retry with backoff. No automatic deletion or retention is performed. Use a dedicated volume with an OS/filesystem quota as well: another process writing to the same filesystem can race a free-space check, and filesystem errors can still occur after admission. Directory writers that bypass `.hec.lock` do not participate in Python's in-process quota lock. The hardened Go CLI now takes the same advisory lock and refuses to share a live Python directory.

GET `/services/collector/ready` is an unauthenticated storage-readiness endpoint in both implementations: it checks capacity and temporary-file creation, returning 200 when available and 503 when unavailable. `/services/collector/health` remains a cheap liveness endpoint. Readiness does not reserve capacity for a future batch or test all filesystem operations.

Security outcomes are written to stderr as JSON records with a timestamp prefix. They include normalized endpoints, direct peer IPs, outcome/status, and generated request IDs where available. Tokens, bodies, raw URLs, and query values are excluded. Individual security records are limited to 10/second with a burst of 20; count summaries (including suppressed records) are emitted every 30 seconds when there is activity and at shutdown. Collect these logs in your monitoring system and alert on authentication failures, connection saturation, storage rejection, and readiness failures. External alert delivery and log rotation remain deployment responsibilities.

Python supports chunked uploads and closes each connection after responding. SIGINT/SIGTERM stops admission, allows active workers ten seconds to finish, and disconnects remaining sockets. Socket deadlines cannot cancel an OS filesystem operation already in progress; bounded batches and storage checks limit that work. A client timeout or retry can still produce duplicate events.

## Send events

```sh
curl http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk $HEC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event":"hello"}'
```

Relative `-events-dir` paths resolve against the process working directory. Starting from `python/` with the default `./events` stores files in `python/events/`. Use an absolute path to keep storage independent of the launch directory.

## HTTPS

Supply a PEM certificate and private key. To run HTTP and HTTPS simultaneously:

```sh
python3.14 hec.py -http-addr :8088 -https-addr :8443 \
  -tls-cert server.crt -tls-key server.key -events-dir ./events
```

Disable HTTP with `-http-addr ''`. HTTPS requires TLS 1.2 or newer. For local testing, generate a self-signed certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 30 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
curl --cacert server.crt https://localhost:8443/services/collector/event \
  -H "Authorization: Splunk $HEC_TOKEN" -d '{"event":"hello over TLS"}'
```

## Configuration

| Flag | Default | Purpose |
| --- | --- | --- |
| `-http-addr` | `127.0.0.1:8088` | HTTP bind address; empty disables |
| `-https-addr` | empty | HTTPS bind address; empty disables |
| `-tls-cert`, `-tls-key` | empty | PEM certificate and key |
| `-events-dir` | `./events` | Created automatically with mode 0700 |
| `-token` | `HEC_TOKEN` environment variable | Required authentication token |
| `-no-auth` | false | Explicitly allow unauthenticated ingestion |
| `-max-body-bytes` | 10485760 | Limit for both wire and decompressed bodies |

Use `127.0.0.1:8088` to restrict HTTP to local clients. Token and `-no-auth` cannot be combined. SIGINT and SIGTERM trigger graceful shutdown with a ten-second deadline.

## Protocol and storage

- POST `/services/collector`, `/services/collector/event`, or `/services/collector/event/1.0`, optionally with a trailing slash.
- Authenticate with `Authorization: Splunk <token>`.
- Send one JSON object or concatenated/newline-separated JSON objects, each with a nonempty string or object `event` field. Top-level arrays are not accepted by the HEC protocol.
- Gzip request bodies are supported with `Content-Encoding: gzip`.
- Full event envelopes, including unknown metadata and numeric precision, are preserved. Query parameters `host`, `source`, `sourcetype`, `index`, and `time` provide defaults when absent from an envelope.
- Each accepted request creates one uniquely named `events-*.json` file containing an array of envelopes, even for a single event. Files have mode 0600. A batch is fully validated before writing; invalid batches store nothing.
- Temporary `.pending-*` files are atomically published after writing. A process crash can leave temporary files, which consumers should ignore. Directory entries are not fsynced, so power-loss durability is filesystem-dependent. Client retries can create duplicates; there is no deduplication or automatic retention.
- GET `/services/collector/health` (also `/health/1.0`) returns code 17 while the process is serving. It is a liveness check, not an ongoing disk-space check.
- POST `/services/collector/ack` returns HEC code 14 (`ACK is disabled`). Configure clients with indexer acknowledgment disabled.

This implements the JSON ingestion subset of [Splunk's HEC endpoint protocol](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/9.4/input-endpoints/input-endpoint-descriptions). Raw ingestion, indexer acknowledgments, token management, index validation, timestamp extraction, and Splunk indexing/search are not implemented. Metadata is stored without applying Splunk indexing semantics. Authentication uses the Splunk header scheme; Basic and query-string authentication are not supported.

## Test

Run from this directory with a supported interpreter:

```sh
python3.14 -m unittest -v test_hec.py
```

HTTPS tests use `openssl` to create a temporary certificate. Tests cover HTTP/HTTPS, authentication, batches, numeric precision, gzip/chunking, concurrency caps, deadlines, expanded-output limits, quotas and recovery, rate limits, audit redaction/sampling, filesystem failures, runtime validation, and real CLI startup/shutdown.

See the [Python security review](security_best_practices_report.md) for findings and remediation evidence.
