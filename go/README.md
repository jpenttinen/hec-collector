# Go HEC receiver

Standard-library-only Go implementation of Splunk HEC JSON ingestion over HTTP/HTTPS, storing events in local JSON files. Requires a current patched **Go 1.26.8+** on Linux/macOS. Rebuild deployed executables after toolchain security updates.

Run all commands below from the `go/` directory (`cd go` from the repository root). The Python implementation is independent in [../python](../python/README.md).

## Run

```sh
go build -o bin/hec .
export HEC_TOKEN='replace-with-your-token'
./bin/hec -events-dir ./events
```

```sh
curl http://localhost:8088/services/collector/event \
  -H "Authorization: Splunk $HEC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"time":1750000000.123,"host":"example","sourcetype":"app:json","event":{"message":"hello"}}'
```

Success returns HTTP 200 with `{"text":"Success","code":0}` only after the file has been written, synced, closed, and atomically published.

Relative events directories resolve against the working directory where you start the server. For example, starting from `bin/` with the default `./events` writes to `bin/events/`. Startup logs show the absolute storage path. To always write to a specific location, use an absolute path:

```sh
./bin/hec -events-dir /absolute/path/to/events
```

## Security limits

Go uses the common authentication, listener, and body flags below, plus:

| Flag | Default | Behavior |
| --- | --- | --- |
| `-max-connections` | 32 | Shared HTTP/HTTPS connection cap, enforced before worker allocation or TLS handshake; excess sockets close |
| `-max-inflight` | 8 | Concurrent ingestion requests; overload returns 503 without an unbounded queue |
| `-requests-per-second` | 100 | Shared ingestion/ACK/readiness attempts per second, including invalid authentication; burst equals rate |
| `-max-expanded-bytes` | 10485760 (10 MiB) | Exact compact JSON array size, including delimiters, escaping, and final newline |
| `-max-events` | 10000 | Events per batch |
| `-max-query-bytes` | 8192 | Encoded query size; at most 32 fields |
| `-max-metadata-bytes` | 1024 | Bytes per decoded query-default value |
| `-max-storage-bytes` | 10737418240 (10 GiB) | Logical bytes of direct event-directory entries, including orphan pending files; excludes `.hec.lock` |
| `-max-files` | 100000 | Direct directory entries, excluding `.hec.lock` |
| `-min-free-bytes` | 268435456 (256 MiB) | Free-space reserve before a write |
| `-min-free-inodes` | 1024 | Free-inode reserve when filesystem inode totals are available |

Limits must be positive; `-max-expanded-bytes` must be at least 3 and `-max-body-bytes` less than MaxInt64. Defaults are parsed once, and the expanded batch and event-count limits are checked before storage allocation. Invalid or oversized batches publish no file. Query size/field/value violations (including malformed query encoding) and expanded batch violations return 413. Compact output replaces the previous Go pretty-printing; event values and numeric precision are preserved.

Storage admission and writes are serialized. Each write scans direct entries with bounded directory-read buffers, which recognizes existing files on restart and operator-managed deletion. This costs more work as the directory grows. The service requires ownership of the events directory, refuses group/world-writable directories, and validates a private regular `.hec.lock` file. Existing permissions are never silently changed. Filesystem operations use an open directory handle, and atomic hard-link publication refuses to overwrite an existing event. Publication briefly creates a second name for the same inode before removing the pending name; the entry cap applies to the resulting directory after cleanup. The resolved directory is validated; deployment should keep parent-directory permissions and ACLs trusted. POSIX `flock`, filesystem statistics, and hard links are required (Linux/macOS). Keep the directory flat; quotas count direct entries, not recursive contents.

Go and Python now use the same `.hec.lock`. Do not remove it or run independent writers against that directory. Other processes writing to the same filesystem can race a free-space check, so use a dedicated volume with an OS/filesystem quota and operator-managed retention. No automatic deletion occurs. Admission/rate/quota failures and filesystem ENOSPC/EDQUOT errors return 503 with `Retry-After: 1`; clients should back off. Other filesystem failures return 500. Readiness checks capacity and temporary-file creation, returns 503 while a write holds the storage lock, and does not reserve space or guarantee future publication. Liveness remains independent of storage.

HTTP defaults to loopback. For remote ingestion, enable HTTPS and disable HTTP, or restrict the backend to a trusted TLS proxy. Configuring HTTPS alone does not disable HTTP. The Go header/TLS deadline is 5 seconds, request-read/write deadlines 30 seconds, idle deadline 60 seconds, and header budget 32 KiB. Body limits cover both wire and decompressed data. CPU work checks cancellation between events; socket deadlines cannot interrupt a filesystem operation already running. The ten-second shutdown deadline may leave pending files if the process exits with unfinished work.

Go emits structured security records on stderr with generated request IDs, fixed endpoint/outcome labels, status, and direct peer IP. Tokens, bodies, raw paths/query values, forwarded headers, and client-supplied request IDs are excluded. Individual records are limited to 10/second with a burst of 20; aggregate counts and suppressed totals are emitted every 30 seconds with activity and at shutdown. Startup messages are plain text. Collect and rotate these logs and alert on authentication failures, connection saturation, unavailable storage, and server errors. Pre-handler HTTP parsing/TLS errors do not have application request records; configure edge monitoring for those. CLI help/error output never uses the environment token as a flag default. Prefer `HEC_TOKEN` to putting secrets in command arguments.

## HTTPS

Supply a PEM certificate and private key. To run HTTP and HTTPS simultaneously:

```sh
./bin/hec -http-addr :8088 -https-addr :8443 \
  -tls-cert server.crt -tls-key server.key -events-dir ./events
```

Disable HTTP with `-http-addr ''`. HTTPS requires TLS 1.2 or newer. Go accepts only AEAD cipher suites for TLS 1.2; TLS 1.3 uses Go's standard policy. Legacy 3DES and CBC-only TLS clients are rejected. For local testing, generate a self-signed certificate:

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

Run from this directory:

```sh
go test -race ./...
go vet ./...
govulncheck ./...
```

The [Go security workflow](../.github/workflows/go-security.yml) runs these checks from `go/` on Linux and macOS for pushes and pull requests. It selects the current Go 1.26 patch and pins action commits and the scanner version. Keep those pins maintained. Install the scanner with `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0` using standard module checksum verification.

Tests cover HTTP/HTTPS, authentication, numeric precision, gzip, expanded-output boundaries, metadata escaping, concurrent quotas and retention recovery, low-space/inode rejection, directory/lock safety, audit redaction/sampling, connection and ingestion admission, legacy TLS rejection, and real CLI startup, deadlines, readiness, and shutdown.

See the [Go security review](go_security_review.md) for findings and remediation evidence.
