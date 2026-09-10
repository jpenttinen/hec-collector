<!-- Source and documentation paths updated after the go/ and python/ directory split. -->

# Python HEC security review and remediation

## Remediation status — 2026-09-09

The six findings below now have implementation changes and regression coverage in the Python receiver. **24 tests pass on Python 3.14.6**, including real CLI startup, ingestion to disk, graceful shutdown, and HTTPS with certificate and hostname verification. This is targeted remediation, not a claim of complete OWASP compliance.

| Original finding | Implemented change | Current code |
| --- | --- | --- |
| 1. Unbounded workers | Shared admission cap across HTTP/HTTPS; refusal before worker creation; absolute header/TLS and request socket deadlines; controlled worker-allocation failure | [Connections](/Users/jyrki/Documents/git-repos/hec/python/hec.py:74), [Server](/Users/jyrki/Documents/git-repos/hec/python/hec.py:479) |
| 2. Expanded batch amplification | Query length/field/value limits, event-count limit, exact serialized-output accounting before publication; incremental output writes | [Collector.ingest](/Users/jyrki/Documents/git-repos/hec/python/hec.py:229) |
| 3. Disk/inode exhaustion | Configurable byte/file quotas and free-space/inode reserves; serialized check/write; directory writer lock; request rate limit; 503 backpressure and storage readiness | [Collector](/Users/jyrki/Documents/git-repos/hec/python/hec.py:158) |
| 4. Missing security audit | Structured redacted events, fixed-cardinality counters, rate-limited individual logs, periodic summaries, controlled parser error logging | [Audit](/Users/jyrki/Documents/git-repos/hec/python/hec.py:38), [Handler.respond](/Users/jyrki/Documents/git-repos/hec/python/hec.py:325) |
| 5. Unsupported Python minimum | CLI refuses Python older than 3.12, logs runtime/OpenSSL versions, and documentation requires current patches; regression tests ran with a supported interpreter | [main](/Users/jyrki/Documents/git-repos/hec/python/hec.py:561) |
| 6. Uncontrolled exceptions | Numeric length/exponent bounds, Decimal exception handling, and outer connection-error handling including response writes from exception blocks | [number](/Users/jyrki/Documents/git-repos/hec/python/hec.py:148), [Handler.handle](/Users/jyrki/Documents/git-repos/hec/python/hec.py:304) |

Additional changes: Python HTTP defaults to `127.0.0.1:8088`; startup checks directory ownership/write permissions; server startup avoids blocking reverse DNS; the HTTP Server header no longer exposes the Python version. The Go server was not changed by this remediation.

Validation: `/opt/homebrew/bin/python3.14 -m unittest -v test_hec.py` — **24 passed**. Original tests were retained and extended with security cases. The HTTPS test certificate was updated to satisfy modern strict certificate verification instead of weakening client verification.

Operational responsibilities remain: use external HTTPS or trusted proxy termination, run a patched interpreter/OpenSSL, collect and rotate logs and configure alerts, and place events on a dedicated quota-limited volume. There is no automatic event deletion. Python's lock must not be bypassed by another writer; do not run Go against the same directory. A filesystem operation already in progress cannot be interrupted by the socket deadline. Readiness and free-space checks cannot guarantee a future write when unrelated filesystem users consume space.

See [README configuration](/Users/jyrki/Documents/git-repos/hec/python/README.md) for new defaults and flags. The original review follows as historical evidence: its severity counts, hashes, test results, and line references describe the pre-remediation revision, not the current file positions.

---

# Original review (before remediation)

Date: 2026-09-09

## Executive summary

The Python receiver needs hardening before direct exposure to untrusted networks. This review identified **two high, three medium, and one low severity findings**. The highest priorities are unbounded connection workers and amplification of query metadata into stored events. Both were confirmed with bounded localhost checks. No authentication bypass, remote code execution, or path traversal was demonstrated.

Scope: `hec.py`, `test_hec.py`, and Python deployment instructions in `README.md`. The Go server was not audited. Reviewed `hec.py` SHA-256: `89ce73c67dbad208bc4341abab26d1b1c9806e946711508ed02812c18fb81720`.

The mapping uses [OWASP Top 10:2025](https://owasp.org/Top10/), the current edition. OWASP categories are an assessment framework, not a certification or a guarantee that every vulnerability has been found. Severity assumes clients can reach the listener; findings requiring an ingestion token state that explicitly. Firewall, reverse proxy, storage quota, and runtime patching controls outside this repository were not inspected.

The security-best-practices skill has no reference specific to Python's standard-library HTTP server; this review uses source inspection, bounded tests, and official Python/OWASP documentation instead. No implementation changes were made.

## High severity

### 1. Unauthenticated clients can allocate unbounded worker threads

**OWASP:** A06 Insecure Design; A02 Security Misconfiguration.

**Evidence:** [Server inheritance](/Users/jyrki/Documents/git-repos/hec/python/hec.py:223), [socket timeout](/Users/jyrki/Documents/git-repos/hec/python/hec.py:95), [TLS worker](/Users/jyrki/Documents/git-repos/hec/python/hec.py:234).

`ThreadingHTTPServer` starts a new thread for each accepted connection. This implementation has no concurrent-connection cap, bounded worker pool, or admission control. Thread allocation and header parsing precede authentication. The 30-second socket timeout is an inactivity timeout, not an absolute deadline for receiving the request headers/body. HTTP clients can prolong reads by periodically sending bytes; TLS connections also allocate workers before authentication.

**Impact:** An unauthenticated client can consume threads, file descriptors, and memory, preventing legitimate ingestion. This remains possible with a strong HEC token.

**Verified:** Eight incomplete HTTP header requests, carrying no Authorization header, created eight additional live worker threads. The test stopped at eight connections; exhaustion was not attempted. The absence of a cap was also verified in the inherited `ThreadingMixIn.process_request` implementation.

**Fix:** Bound connections before worker allocation, reject overload, and enforce absolute header/body deadlines. Use a maintained production HTTP server or a restricted listener behind a proxy with explicit connection, timeout, and rate limits. Python itself states that [`http.server` is not recommended for production](https://docs.python.org/3/library/http.server.html). A proxy only mitigates this if clients cannot bypass it.

### 2. Query defaults amplify small batches beyond the request size limit

**OWASP:** A06 Insecure Design.

**Evidence:** [Per-event query defaults](/Users/jyrki/Documents/git-repos/hec/python/hec.py:59), [in-memory accumulation and join](/Users/jyrki/Documents/git-repos/hec/python/hec.py:66), [storage serialization](/Users/jyrki/Documents/git-repos/hec/python/hec.py:81), [body-only limit](/Users/jyrki/Documents/git-repos/hec/python/hec.py:119).

The limit covers compressed and decompressed request bodies. It does not cover query defaults multiplied by the number of events. Each event missing `host`, for example, receives a new copy of the `host` query value. All expanded envelopes are retained in memory, then joined into another large string before writing. There is no event-count, metadata-length, or expanded-batch limit.

**Impact:** A client with a valid token, or any client when `-no-auth` is enabled, can induce disproportionate memory and disk use with requests below the configured body limit. Larger batches can exhaust memory before a file is written.

**Verified over HTTP:** With `max_bytes=1024`, a 910-byte body containing 70 concatenated `{"event":"x"}` objects and a 2,000-character `host` query value returned HTTP 200 and produced **141,823 bytes** on disk. Query bytes are additional input, so this is approximately 49 times the body-plus-query input, or 156 times the body alone. The test wrote only this small temporary file.

**Fix:** Limit query length, metadata values, and events per batch; account for the entire serialized output as defaults are added; reject before exceeding a configured expanded-batch ceiling. Write incrementally to the unpublished temporary file to avoid the final full-size string copy while retaining all-or-nothing publication. Ordinary ingress body limits alone do not solve this.

## Medium severity

### 3. Valid ingestion can exhaust disk space or inodes without backpressure

**OWASP:** A06 Insecure Design; A10 Mishandling of Exceptional Conditions.

**Evidence:** [Unconditional file creation](/Users/jyrki/Documents/git-repos/hec/python/hec.py:74), [health response](/Users/jyrki/Documents/git-repos/hec/python/hec.py:180), [storage error handling](/Users/jyrki/Documents/git-repos/hec/python/hec.py:210).

Every accepted request creates another permanent file. There is no total storage quota, ingestion rate limit, free-space reserve, inode budget, or retention policy in the application. This is distinct from finding 2: normal, unexpanded requests can eventually consume the filesystem. The health endpoint continues returning healthy when writes fail; the README correctly labels it liveness-only, but no separate readiness signal exists.

**Impact:** A compromised producer token or malfunctioning authorized sender can stop event ingestion and potentially affect other processes sharing the filesystem. This requires a valid token unless authentication was explicitly disabled. External quotas/retention can mitigate the risk; their absence in the deployment has not been established.

**Verification:** Static inspection and the existing storage-failure test. No disk-filling test was performed.

**Fix:** Configure a dedicated quota-limited volume, byte/inode monitoring, and ingestion backpressure. Add storage-aware readiness and alerting. Define retention explicitly with the operator; do not silently delete historical events as a default remediation. Concurrent quota enforcement must reserve capacity rather than rely solely on a racy free-space check.

### 4. Authentication failures and rejected requests have no security audit trail

**OWASP:** A09 Security Logging and Alerting Failures.

**Evidence:** [Authentication rejection](/Users/jyrki/Documents/git-repos/hec/python/hec.py:193), [HEC error response](/Users/jyrki/Documents/git-repos/hec/python/hec.py:206), [disabled request logging](/Users/jyrki/Documents/git-repos/hec/python/hec.py:218).

`log_message` discards all ordinary request logs. Wrong/missing tokens, oversized requests, malformed JSON, and other HEC rejections return responses without recording security events. Startup and filesystem failures are logged, but there are no corresponding security counters or alerts.

**Impact:** Token guessing, repeated abuse, and the onset of an ingestion attack can go unnoticed, and incident investigation lacks attribution and timing evidence.

**Verified:** A request with the wrong token returned HTTP 403 and emitted no captured Python logging output. Static inspection confirms that ordinary HTTP logging is also disabled.

**Fix:** Emit bounded structured security events containing time, direct peer IP, normalized endpoint, outcome code, and a generated request identifier. Add counters and alerts for failures and saturation. Keep tokens, payloads, raw query strings, and arbitrary client-controlled text out of logs; sample/rate-limit repeated errors so logging cannot itself fill the disk. Trust forwarded client addresses only from configured proxies.

### 5. Documented minimum runtime is unsupported upstream

**OWASP:** A03 Software Supply Chain Failures.

**Evidence:** [Documented Python 3.9+ requirement](/Users/jyrki/Documents/git-repos/hec/python/README.md), [standard-library HTTP dependency](/Users/jyrki/Documents/git-repos/hec/python/hec.py:19).

The local `python3` used for this review reports **Python 3.9.6**, and the README recommends a minimum of 3.9. Python 3.9 reached upstream end of life on **2025-10-31**, according to the [Python version support table](https://devguide.python.org/versions/). Having no third-party packages does not eliminate reliance on the interpreter, HTTP parser, OpenSSL, and compression libraries.

**Impact:** The documented setup permits a runtime that no longer receives upstream security fixes. This is a verified lifecycle/configuration issue, not a claim of a specific exploitable CVE in this deployment. Vendor backports and the runtime used for an independently deployed service were not verified.

**Fix:** Set and test a supported minimum, preferably Python 3.12+ with current patch releases, and document interpreter/OpenSSL update ownership. Use an explicit interpreter or managed environment rather than assuming the OS-provided `python3` is current. Record runtime versions in deployment checks.

## Low severity

### 6. Numeric parsing and disconnected error responses escape controlled handling

**OWASP:** A10 Mishandling of Exceptional Conditions.

**Evidence:** [Decimal parsing](/Users/jyrki/Documents/git-repos/hec/python/hec.py:41), [parser catch list](/Users/jyrki/Documents/git-repos/hec/python/hec.py:68), [response inside exception handler](/Users/jyrki/Documents/git-repos/hec/python/hec.py:206).

A numeric literal with an exponent outside the Decimal implementation's range can raise `decimal.InvalidOperation`. That exception is not in either relevant catch list. Separately, a `BrokenPipeError` raised while sending an error response inside the `except HECError` block is not caught by the sibling `except ConnectionError` block.

**Verified:** An authenticated body `{"event":{"n":1e9999999999999999999}}` produced `decimal.InvalidOperation`, a server-side traceback, and `RemoteDisconnected` at the client instead of a JSON error. Closing incomplete HTTP connections also produced uncaught `BrokenPipeError` tracebacks during error responses.

**Impact:** Invalid input and routine disconnects cause uncontrolled connection failures and noisy stderr tracebacks. Repeated occurrences can amplify log volume or client retries. The tests did **not** crash the overall server or bypass authentication; the numeric case requires authorization.

**Fix:** Catch relevant `decimal.DecimalException` errors as invalid data and add numeric bounds. Guard response writes against disconnected clients at an outer request boundary. Return a controlled HEC error for invalid numeric input and record bounded diagnostic counters, without blanket catches that turn programming errors into success.

## Coverage across the OWASP Top 10:2025

| Category | Assessment of this implementation |
| --- | --- |
| A01 Broken Access Control | Ingestion requires a token by default; no file-serving/read endpoint, user-controlled output path, or bypass was found. Public health is intentional. The single shared token grants ingestion access, not per-tenant authorization. |
| A02 Security Misconfiguration | Finding 1. Review deployment exposure, explicit `-no-auth`, file ownership, and permissions. The default binds plain HTTP to all IPv4 interfaces; see the conditional transport note below. |
| A03 Software Supply Chain Failures | Finding 5. Standard-library-only dependencies reduce package exposure but do not remove runtime patching requirements. |
| A04 Cryptographic Failures | TLS has a 1.2 minimum and uses Python's server SSL context; token comparison uses `hmac.compare_digest`. Transport deployment and at-rest encryption were not established. |
| A05 Injection | No shell execution, SQL, dynamic evaluation, or outbound URL fetching in request processing. Metadata is JSON-encoded. Stored payloads remain untrusted for any future viewer or downstream processor. No direct injection exploit found. |
| A06 Insecure Design | Findings 1–3: connection limits, output expansion, and storage capacity. |
| A07 Authentication Failures | Correct rejection of absent, malformed, and wrong tokens was tested. No guessing throttle or entropy policy exists; use generated high-entropy tokens and edge rate limits. No bypass demonstrated. |
| A08 Software or Data Integrity Failures | Files are mode 0600, fsynced, and atomically published without overwriting an existing final name. No unsafe object deserialization. Duplicate JSON keys are accepted and raw envelopes preserve them; downstream interpretation and tamper-evident archival are not guaranteed. No downstream exploit was tested. |
| A09 Security Logging and Alerting Failures | Finding 4. |
| A10 Mishandling of Exceptional Conditions | Findings 3 and 6. Existing malformed JSON, gzip, and storage-failure tests exercise some controlled error paths. |

### Conditional transport and filesystem concerns

HTTP support is an explicit product requirement, so its existence is not itself a vulnerability. However, the default `:8088` listener is unencrypted and remains active when HTTPS is also enabled unless `-http-addr ''` is supplied. If clients use that listener over an untrusted network, their reusable token and event content are exposed to on-path observers. Use HTTPS-only externally, or bind HTTP to a trusted local proxy interface with appropriate network restrictions. Proxy TLS termination and network isolation were not inspected, so this is a deployment-dependent risk, not an additional confirmed finding. See [listener defaults](/Users/jyrki/Documents/git-repos/hec/python/hec.py:256).

The server creates a new events leaf directory with mode 0700 and files with mode 0600, but it does not repair permissions or verify ownership of an existing directory. Use a directory owned by the service account and not writable by other users; atomic publication does not protect against a local actor who controls the storage directory. This review did not change directory permissions or inspect event contents.

## Validation and limits

- Existing suite: `python3 -m unittest -v test_hec.py` — **9 tests passed**, including HTTPS, auth errors, concurrent writes, gzip, chunked requests, and storage failure.
- Bounded custom localhost checks: eight incomplete-header connections → eight worker threads; 910-byte authenticated batch → 141,823-byte JSON file; wrong token → 403 with no security log; extreme exponent → disconnected response and Decimal exception.
- A request carrying both `Content-Length` and `Transfer-Encoding` was rejected with HTTP 400. This check does not constitute exhaustive request-smuggling testing across proxies.
- All probe files were temporary. No existing event files were modified. No production listener was tested, no destructive exhaustion was attempted, and no exploit-based CVE scan was performed.
- The test harness initially sent malformed chunk framing when trying to test conflicting framing; that harness error was corrected and the explicit conflicting-header check passed.

## Recommended order

1. Bound connections and absolute request duration; restrict direct exposure.
2. Limit batch count, metadata length, and total expanded bytes.
3. Establish storage quotas/backpressure and structured security monitoring.
4. Move to a supported patched runtime and cover numeric/disconnect exception paths.
5. Re-run functional tests and add regression checks for each corrected finding.
