<!-- Source and documentation paths updated after the go/ and python/ directory split. -->

# Go HEC security remediation — 2026-09-10

All eight findings in the original review below now have implementation changes and regression coverage. Both local executables, `hec` and `bin/hec`, were rebuilt with **Go 1.26.8** and are byte-identical. Their build metadata no longer includes the Go 1.22 legacy defaults. The system-wide Go installation was not changed.

| Original finding | Remediation | Current implementation |
| --- | --- | --- |
| 1. Batch expansion | Parse queries once; cap query fields/bytes, metadata bytes, event count, and exact compact output bytes; reject before publication; incremental file writes without a second whole-batch encoding | [Query validation](/Users/jyrki/Documents/git-repos/hec/go/hec.go:233), [expanded size](/Users/jyrki/Documents/git-repos/hec/go/hec.go:160), [storage](/Users/jyrki/Documents/git-repos/hec/go/storage.go:191) |
| 2. Vulnerable toolchain | Require Go 1.26.8+, rebuild both executables, and add a Linux/macOS security workflow with pinned actions and scanner version | [go.mod](/Users/jyrki/Documents/git-repos/hec/go/go.mod:3), [workflow](/Users/jyrki/Documents/git-repos/hec/.github/workflows/go-security.yml:1) |
| 3. CLI token disclosure | Load the environment token after parsing; help has no secret default; parse errors exclude argument values; preserve explicit empty-token semantics | [Configuration](/Users/jyrki/Documents/git-repos/hec/go/main.go:27) |
| 4. Legacy TLS ciphers | Modern module compatibility baseline plus explicit AEAD-only TLS 1.2 suites; TLS 1.3 remains enabled | [TLS policy](/Users/jyrki/Documents/git-repos/hec/go/main.go:88) |
| 5. Unbounded storage | Serialized byte/file quotas and free-space/inode reserves; account for existing/orphan files and retention; common Go/Python directory lock; 503 backpressure and separate readiness endpoint | [Capacity](/Users/jyrki/Documents/git-repos/hec/go/storage.go:119), [readiness](/Users/jyrki/Documents/git-repos/hec/go/storage.go:174) |
| 6. Unbounded admission | Shared HTTP/HTTPS connection cap before worker/handshake allocation, separate ingestion cap, and rate limiting; retain absolute network deadlines | [Listener](/Users/jyrki/Documents/git-repos/hec/go/limits.go:61), [ingestion](/Users/jyrki/Documents/git-repos/hec/go/hec.go:115) |
| 7. Unsafe directory | Validate ownership and write permissions, validate and lock a private regular lock file, anchor operations to an open directory, and publish without overwriting existing files | [Storage initialization](/Users/jyrki/Documents/git-repos/hec/go/storage.go:27) |
| 8. Missing audit | Structured redacted events with generated IDs and fixed labels; bounded event rate; aggregate counts/suppression summaries every 30 seconds and at shutdown | [Audit logger](/Users/jyrki/Documents/git-repos/hec/go/limits.go:135) |

Validation completed locally:

- **19 top-level Go tests**, including security subtests, pass under `go test -race ./...`. Real CLI checks cover simultaneous HTTP/HTTPS, certificate verification, quota and readiness recovery, combined connection admission, stalled HTTP/TLS deadlines, secret redaction, directory rejection, and graceful shutdown.
- `go vet ./...` passes. A Linux/amd64 cross-build succeeds; Linux runtime tests are configured in CI but have not been executed here.
- `govulncheck ./...` reports **No vulnerabilities found** using Go 1.26.8. A binary-mode scan of the rebuilt `hec` also reports **No vulnerabilities found**; `bin/hec` is byte-identical.
- Regression tests check exact/overflow output boundaries, escaped query amplification, concurrent byte/file quota races, orphan/restart accounting, retention recovery, free-space/inode limits, ENOSPC/EDQUOT backpressure, lock exclusivity, directory permissions, cancellation, audit sampling, CLI help, and rejection of 3DES/CBC/TLS 1.1 while accepting verified TLS 1.2 AEAD and TLS 1.3 connections.

See [Go limits and migration notes](/Users/jyrki/Documents/git-repos/hec/go/README.md). Behavior changes: HTTP now defaults to loopback; existing writable directories must satisfy the security checks; output is compact JSON; oversized work is rejected with 413; temporary overload/storage pressure returns 503 with retry advice. Defaults are 32 connections, 8 concurrent ingestion requests, 100 attempts/second, 10 MiB expanded batches, 10,000 events/batch, 10 GiB stored logical bytes, and 100,000 stored entries.

Operational responsibilities remain: replace/restart any separately deployed or already-running old executable; use HTTPS or a restricted TLS proxy for remote traffic; maintain the patched build/scanner/action versions; collect, rotate, and alert on security logs; use a dedicated quota-limited volume and operator-managed retention. Parent-directory permissions and ACLs must be trusted. Go/Python writers must not bypass or delete `.hec.lock`. Quotas count direct entries rather than recursive content. Hard-link publication briefly adds another name for the same inode before pending cleanup. Other filesystem writers can race reserve checks; socket deadlines cannot cancel an OS filesystem operation already in progress. Readiness does not guarantee a subsequent write, directory entries are not fsynced, and client retries can duplicate events. No production service was restarted by this work.

The Python implementation and its separate review were preserved. The original review follows as historical evidence: its severity totals, code positions, hashes, old-toolchain results, and statements about missing controls describe the pre-remediation source, not the current implementation. This remediation is not a claim of comprehensive OWASP certification.

---

# Go HEC security review — OWASP Top 10:2025

Date: 2026-09-10

## Executive summary

The Go receiver needs additional hardening before exposure to untrusted clients. This review identified **two high and six medium severity findings**. Prioritize bounded batch expansion and rebuilding with a patched Go toolchain. Additional confirmed issues include environment-token disclosure in CLI usage, negotiable 3DES, unsafe existing-directory acceptance, and missing authentication audit logs.

Scope: `main.go`, `hec.go`, `hec_test.go`, `go.mod`, Go instructions in `README.md`, and build metadata in `hec` and `bin/hec`. The existing Python security report and implementation were preserved. No Go implementation, configuration, binary, or existing test was changed.

The mapping uses the current [OWASP Top 10:2025](https://owasp.org/Top10/2025/). This is an evidence-based review, not OWASP certification. Severity assumes the relevant listener is reachable; authentication, certificate, and local-access prerequisites are stated per finding. Deployment firewalls, proxies, volume quotas, log collectors, and actual production binaries were not inspected. No remote authentication bypass, code execution, or request-controlled filesystem traversal was demonstrated.

## High severity

### 1. Query defaults amplify batches beyond the body limit

**Rule ID:** GO-REVIEW-001; GO-HTTP-002. **OWASP:** A06 Insecure Design.

**Location:** [collector.ServeHTTP, hec.go:104](/Users/jyrki/Documents/git-repos/hec/go/hec.go:104), [metadata expansion, hec.go:134](/Users/jyrki/Documents/git-repos/hec/go/hec.go:134), [store serialization, hec.go:171](/Users/jyrki/Documents/git-repos/hec/go/hec.go:171).

**Evidence:** Each event executes `r.URL.Query().Has(key)` and `json.Marshal(r.URL.Query().Get(key))`, then appends its expanded JSON to `events`. Query parsing repeats for each missing field in each event. There is no event-count, metadata-length, or expanded-output limit. `encoder.SetIndent("", "  ")` adds further output expansion; JSON serialization buffers data in memory. Socket write deadlines do not cancel this CPU/memory work.

**Verified:** In a copied source tree, a valid-token request with 100 events, a **1,300-byte body**, and a **32,773-byte query** returned 200 and produced **3,281,003 bytes** on disk with `maxBytes=4096`. The query also fits the actual server's 1 MiB header budget. The test used approximately 3.3 MB of output; memory or disk exhaustion was not attempted.

**Impact:** A valid-token client, or any client with `-no-auth`, can make bounded requests consume disproportionate CPU, memory, and disk. Larger or concurrent batches can terminate the process through memory exhaustion.

**Fix:** Parse the query once. Bound encoded query size, field count, metadata size, event count, and exact serialized batch size including whitespace/escaping before publication. Use bounded incremental serialization into a private temporary file, and remove it if validation or limits fail. Return 413 without publishing a batch.

**Mitigation / qualification:** Restrict ingestion clients and impose query, body, and concurrency limits at the proxy. A body limit alone does not address multiplication of metadata across events. Existing Python limits do not protect this Go process.

### 2. Existing binaries and current toolchain contain a relevant TLS vulnerability

**Rule ID:** GO-REVIEW-002; GO-DEPLOY-001. **OWASP:** A03 Software Supply Chain Failures.

**Location:** [TLS configuration, main.go:52](/Users/jyrki/Documents/git-repos/hec/go/main.go:52), [server execution, main.go:98](/Users/jyrki/Documents/git-repos/hec/go/main.go:98), [build guidance, README.md:3](/Users/jyrki/Documents/git-repos/hec/go/README.md).

**Evidence:** `go version` and `go version -m` identify **go1.26.4** for the installed compiler and both existing binaries. A successful online `govulncheck ./...` scan reports four symbol-level standard-library advisories. Reachability was manually qualified:

| Advisory | Applicability to this receiver |
| --- | --- |
| [GO-2026-6090 / CVE-2026-56862](https://pkg.go.dev/vuln/GO-2026-6090) | Relevant when HTTPS is enabled. A malicious TLS peer can repeatedly send post-handshake KeyUpdate messages and force key-derivation work before HTTP authentication. Fixed in Go 1.26.6. |
| [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089) | Requires unencrypted HTTP/2 support. This server does not enable it; not counted as a demonstrated remote vulnerability here. |
| [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) | Scanner traces reach ASN.1 parsing through startup certificate loading. These are operator-supplied local files; no attacker-controlled remote certificate parsing path was established. |
| [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856) | Concerns ECH client privacy. No outbound TLS client/ECH configuration exists in the production implementation; not counted as an applicable privacy leak. |

**Impact:** An unauthenticated peer of the HTTPS listener can consume CPU through the affected TLS processing path. The configured deadlines limit connection lifetime but do not supply the missing message-count control. No exploit traffic for this advisory was generated.

**Fix:** Build and redeploy both binaries with a current supported patch release. **Go 1.26.8** is the current patch on the existing release line at review time; 1.26.6 is the minimum fix for the relevant advisory. Update the documented supported-build policy and add vulnerability scanning to CI. Installing a compiler alone does not patch already-built executables. [Go release history](https://go.dev/doc/devel/release).

**Mitigation / qualification:** Terminate TLS at a patched, restricted proxy and keep the backend inaccessible directly until rebuilt. The default HTTP-only mode does not invoke this TLS path. `go 1.22` in `go.mod` is a language/compatibility baseline, not proof the executable was built with Go 1.22; the actual binary metadata is the evidence here.

## Medium severity

### 3. CLI help and argument errors disclose the environment token

**Rule ID:** GO-REVIEW-003; GO-CONFIG-001. **OWASP:** A02 Security Misconfiguration; A09 Security Logging and Alerting Failures.

**Location:** [run, main.go:30](/Users/jyrki/Documents/git-repos/hec/go/main.go:30), [argument parsing, main.go:33](/Users/jyrki/Documents/git-repos/hec/go/main.go:33).

**Evidence:** `flag.String("token", os.Getenv("HEC_TOKEN"), ...)` registers the actual secret as the flag's default. Standard flag usage prints nonempty defaults. Both `-h` and an unknown option printed the synthetic environment token during subprocess tests. No real credentials were used or displayed.

**Impact:** CLI startup mistakes can copy a reusable ingestion credential into stderr, deployment logs, or support output. Someone with access to those outputs can authenticate and submit events. This is not an unauthenticated HTTP disclosure.

**Fix:** Register the flag with an empty public default, parse arguments, then apply the environment fallback while preserving the intended explicit-empty-flag semantics. Test that help, malformed arguments, and startup errors never contain the token. Prefer environment/secret-file loading to command-line secret values.

**Mitigation / qualification:** Restrict diagnostic-log access. If this behavior has occurred with a real token in shared logs, remove the exposed material and rotate that token. Disclosure requires help/error execution in a secret-bearing environment.

### 4. Go 1.22 compatibility defaults allow 3DES with RSA certificates

**Rule ID:** GO-REVIEW-004; GO-DEPLOY-001. **OWASP:** A04 Cryptographic Failures; A02 Security Misconfiguration.

**Location:** [go.mod:3](/Users/jyrki/Documents/git-repos/hec/go/go.mod:3), [run TLS configuration, main.go:52](/Users/jyrki/Documents/git-repos/hec/go/main.go:52).

**Evidence:** `go 1.22` and a TLS configuration without `CipherSuites` retain older cipher defaults under the observed Go 1.26.4 builds. Both binary metadata records include `tls3des=1`. A certificate-verified in-memory TLS 1.2 handshake using an RSA test certificate and the same server configuration successfully negotiated `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`.

**Impact:** Clients can negotiate obsolete 64-bit-block 3DES encryption. Exploitation of its cryptographic weaknesses depends on traffic volume and attack conditions; this test establishes negotiability, not plaintext recovery. TLS 1.2 minimum alone does not exclude this cipher.

**Fix:** Raise the module compatibility baseline to the supported Go release used for deployment, rebuild, and verify legacy suites are rejected. If compatibility prevents that immediately, explicitly disable the legacy default (`tls3des=0` on Go 1.26), or choose a reviewed AEAD-only TLS 1.2 policy. Updating only the Go 1.26 patch version leaves the module compatibility setting to address separately. Go removed 3DES from defaults in 1.23 and documents the compatibility mechanism. [Go GODEBUG documentation](https://go.dev/doc/godebug).

**Mitigation / qualification:** A modern TLS-terminating proxy with a restricted backend removes external access to this negotiation. The confirmed suite requires an RSA certificate; this exact handshake does not apply to an ECDSA-only certificate deployment.

### 5. Accepted requests grow storage without a capacity policy

**Rule ID:** GO-REVIEW-005; application resource-budget review. **OWASP:** A06 Insecure Design; A10 Mishandling of Exceptional Conditions.

**Location:** [collector.store, hec.go:159](/Users/jyrki/Documents/git-repos/hec/go/hec.go:159), [publication, hec.go:182](/Users/jyrki/Documents/git-repos/hec/go/hec.go:182), [health response, hec.go:40](/Users/jyrki/Documents/git-repos/hec/go/hec.go:40).

**Evidence:** Every successful request creates a fresh file and performs `Sync()`. There is no total byte/file quota, free-space/inode reserve, ingestion rate limit, or retention policy in Go. The directory is tested for writability only at startup. The health endpoint always reports liveness without inspecting storage.

**Verified:** A temporary real CLI instance accepted 12 small requests and created 12 persistent files (396 logical bytes). No capacity exhaustion was attempted; absence of admission checks follows from the complete `store` implementation.

**Impact:** A valid-token client, or unauthenticated clients in `-no-auth` mode, can fill the event filesystem or exhaust inodes. On shared storage this can affect other services. Errors return generic 500s after allocation/write attempts fail.

**Fix:** Introduce synchronized byte/file admission limits, free-space/inode reserves, and ingestion rate limits. Account for existing and pending files and simultaneous writers. Use 503/Retry-After for temporary storage pressure and a separate readiness endpoint. Keep liveness cheap. Provide operator-managed retention.

**Mitigation / qualification:** Use a dedicated quota-limited volume with monitoring. External quotas were not inspected. A free-space precheck alone cannot prevent other processes racing to consume storage.

### 6. Connection and ingestion concurrency have no application cap

**Rule ID:** GO-REVIEW-006; application resource-budget review. **OWASP:** A06 Insecure Design.

**Location:** [listener creation, main.go:83](/Users/jyrki/Documents/git-repos/hec/go/main.go:83), [http.Server configuration, main.go:91](/Users/jyrki/Documents/git-repos/hec/go/main.go:91), [body buffering, hec.go:91](/Users/jyrki/Documents/git-repos/hec/go/hec.go:91).

**Evidence:** The program supplies raw TCP/TLS listeners to `http.Server.Serve` with no connection admission wrapper, handler semaphore, rate limiter, or bounded ingestion queue. Limits on individual request bodies and deadlines do not bound simultaneous allocations.

**Verified:** Sixteen simultaneous unauthenticated incomplete-header connections were opened against the real CLI, then completed successfully. This bounded check is only an illustration of parallel acceptance; the source establishes that no application cap exists. No exhaustion was attempted.

**Impact:** Unauthenticated peers can consume sockets and connection goroutines. Authenticated concurrent uploads additionally multiply body buffers, metadata expansion, and disk work. Go goroutines are lighter than OS threads, and the existing 5-second header, 30-second read/write, and 60-second idle deadlines materially reduce slow-client risk; severity reflects those controls.

**Fix:** Bound total accepted connections across HTTP and HTTPS before expensive work, and independently cap concurrent ingestion. Reject overload promptly instead of queuing unbounded work. Preserve the existing deadlines and use cancellation checks where practical for parsing/serialization.

**Mitigation / qualification:** Verified reverse-proxy connection/rate limits can mitigate this if the backend cannot be reached directly. Their presence was not established in this workspace.

### 7. Existing writable event directories allow local event tampering

**Rule ID:** GO-REVIEW-007; GO-UPLOAD-001. **OWASP:** A01 Broken Access Control; A08 Software or Data Integrity Failures.

**Location:** [directory initialization, main.go:59](/Users/jyrki/Documents/git-repos/hec/go/main.go:59), [writability probe, main.go:63](/Users/jyrki/Documents/git-repos/hec/go/main.go:63), [file publication, hec.go:183](/Users/jyrki/Documents/git-repos/hec/go/hec.go:183).

**Evidence:** `os.MkdirAll(*dir, 0700)` does not change or validate the mode/owner of an existing directory. Startup only tests creation of a probe file. A real CLI subprocess successfully started with a temporary existing directory explicitly set to **0777**, leaving that mode intact.

**Impact:** Another local account able to write the directory can delete or replace event entries or insert forged event files. File mode 0600 protects content reads through the file permissions but does not stop directory-entry replacement by a directory writer. No remote pathname injection is required or claimed.

**Fix:** Validate the effective directory's ownership and permissions at startup; reject group/world-writable event directories unless there is an explicit supported shared-writer design. Resolve and validate the trusted parent/symlink policy. Require a dedicated service account and directory. Do not silently chmod operator-owned existing directories.

**Mitigation / qualification:** A pre-provisioned directory accessible only to the service user avoids this condition. Local directory-write access is required; no privilege escalation beyond that access was demonstrated.

### 8. Authentication failures and ingestion outcomes are not audited

**Rule ID:** GO-REVIEW-008; security audit-logging review. **OWASP:** A09 Security Logging and Alerting Failures.

**Location:** [collector.ServeHTTP authentication branches, hec.go:54](/Users/jyrki/Documents/git-repos/hec/go/hec.go:54), [reply, hec.go:27](/Users/jyrki/Documents/git-repos/hec/go/hec.go:27), [storage-error logging, hec.go:151](/Users/jyrki/Documents/git-repos/hec/go/hec.go:151).

**Evidence:** Authentication rejection, invalid/oversize bodies, and successful ingestion only send responses. The application logs listener startup and storage errors but provides no security outcome counters, request IDs, or peer attribution. A test captured the default logger for three missing-token requests: three 401 responses, **zero log bytes**.

**Impact:** Operators cannot detect or correlate token abuse and repeated malformed requests from application logs. No evidence of external monitoring compensating for the gap was available.

**Fix:** Add structured, redacted audit events and fixed-cardinality counters for authentication, validation, overload, and storage outcomes. Include generated request ID, normalized endpoint, status, and direct peer or explicitly trusted proxy identity. Exclude tokens, raw URLs/query values, and event payloads. Rate-limit logs and summarize suppressed events; configure alerts and rotation in deployment.

**Mitigation / qualification:** Existing proxy logs may cover request status and peer information; verify those controls and alerts. Application logging must not introduce a log-amplification denial of service.

## Coverage across all ten OWASP categories

| OWASP 2025 category | Assessment |
| --- | --- |
| A01 Broken Access Control | Finding 7. HTTP ingestion/ACK checks authentication; health is intentionally public. Metadata does not control output paths. No remote authorization bypass found. |
| A02 Security Misconfiguration | Findings 3 and 4. HTTP defaults to all interfaces; production exposure and TLS termination need deployment verification. |
| A03 Software Supply Chain Failures | Finding 2. Standard-library-only module; no third-party dependency graph or missing-checksum finding. Both existing binaries carry the old toolchain. |
| A04 Cryptographic Failures | Finding 4. TLS minimum is 1.2 and names use crypto/rand. Direct HTTP carries reusable credentials in cleartext; verify a trusted transport boundary. |
| A05 Injection | No SQL, shell, template execution, or outbound request sink in production Go code. JSON is encoded as data. Downstream interpretation of stored events was outside scope. |
| A06 Insecure Design | Findings 1, 5, and 6: expanded-output, aggregate storage, and concurrency limits are absent. |
| A07 Authentication Failures | Startup requires a token or explicit no-auth mode; equal-length tokens use constant-time comparison. Finding 3 can expose credentials operationally. Strong token generation/rotation remains an operator responsibility. |
| A08 Software or Data Integrity Failures | Finding 7. Writes use random names, private temporary files, Sync/Close, and atomic rename. No request-selected filenames. Directory fsync and retry deduplication are documented limitations. |
| A09 Security Logging and Alerting Failures | Findings 3 and 8: credential-bearing CLI diagnostics and absent application audit events. |
| A10 Mishandling of Exceptional Conditions | Finding 5: storage pressure is discovered on write failure. Malformed JSON/gzip and ordinary storage errors are handled; no independent request-triggered panic was demonstrated. Memory exhaustion in finding 1 is not rescued by HTTP panic recovery. |

The API has no cookie authentication, browser UI, or permissive CORS policy; lack of CSRF tokens, cookie flags, CSP, or clickjacking headers is not reported as an applicable vulnerability. The application makes no outbound HTTP requests, so no SSRF path was identified.

HTTP on all interfaces (`main.go:25`) is a deployment concern, especially because enabling HTTPS does not automatically disable HTTP. For local use bind loopback. For remote clients use HTTPS or a trusted TLS proxy with restricted backend access, and disable unnecessary listeners. No production topology was supplied, so missing edge TLS is not counted as an independently proven finding.

## Validation and reproducibility

- `go test -race ./...`: **passed**, including the HTTP/HTTPS and concurrent request tests. Localhost permission was required after the initial sandbox prevented listener binding.
- `go vet ./...`: **passed**.
- `govulncheck ./...`: completed against the public Go vulnerability database and exited 3 for findings. Four symbol-level advisories were reviewed above; the scanner also reported four package-level and two module-level advisories without calls established by its analysis. These are not counted as separate exploitable issues.
- Four bounded audit tests passed in an isolated source copy: query expansion, absent auth logging, synthetic-token disclosure through help/argument errors, and certificate-verified legacy TLS negotiation.
- Temporary CLI checks confirmed existing-directory mode 0777 acceptance, completion of 16 parallel unauthenticated connections, and creation of 12 files from 12 ingestion requests. Temporary CLI event data was deleted and the test process stopped.
- Temporary reproduction sources: `/private/tmp/hec-go-security-review/security_audit_test.go` and `/private/tmp/hec-go-security-review/cli_checks.py`. These demonstrate the observed weaknesses; their passing does **not** mean the weaknesses are fixed. No permanent regression tests were added during this review.
- No production endpoint was contacted and no disk/memory exhaustion was attempted. Runtime vulnerability exploitation, large-scale load testing, and deployment inspection were outside scope.

Reviewed SHA-256 hashes:

```text
main.go      a6414b760f385dee14f9f91a69c786b14f87c054487083e745eb9c8b63841807
hec.go       a46aaa43bfccab62685685c41b895ce8a533b6cdf2a0c78fdf7b3f8154349177
hec_test.go  d3dce5dc3d058cd6e0ea69ed8ab28b5c7f538f81af3445dcc18535c0d7d5707a
go.mod       00712dfe844a85f1c5e5eeab3a705aeb488ffb1a870af4452e499d86e5870a4b
```

Recommended order: patch/rebuild the toolchain and bound expanded batches; remove CLI secret disclosure and legacy TLS defaults; then add aggregate capacity/admission controls, validate storage permissions, and implement redacted audit logging. Porting Python's analogous controls requires Go-specific implementation and testing rather than assuming the Python remediation protects both servers.
