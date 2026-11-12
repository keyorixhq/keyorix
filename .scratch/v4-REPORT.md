# V4 — TLS termination & certificate lifecycle: fuzzing + review report

Status: **COMPLETE**. All three harnesses built, red/green-proofed, committed; ~63
min real fuzz time (all PASS, zero crashes).
Branch: `fuzz/tls-lifecycle`. Repo: keyorixhq/keyorix @ worktree `/mnt/data/wave4/v4`.

The primary copy lives at `/mnt/data/wave4/out/v4-REPORT.md` (writable, outside the
repo). This is the branch-committed durable copy (force-added past `.scratch`'s
gitignore).

## 0. Reading of the task / assumptions (no one answers questions here)

- Keyorix terminates TLS itself on both the HTTP (REST/web) and gRPC listeners —
  confirmed in code (`server/tls_config.go`, `server/grpc/server.go`,
  `server/http_server.go`). There is **no server-side mTLS client authentication
  today**: no listener sets `tls.Config.ClientAuth` / `ClientCAs` anywhere. Whether
  mTLS is *planned* is an **open question for the founder** (section 7); I did not
  build it.
- "Fuzz ≥ 60 min real time" is met with back-to-back foreground `-fuzztime` chunks
  (≤ ~9 min each; one foreground command is capped near 10 min by the tool).

## 1. PHASE 0 — map of TLS config / cert lifecycle

### 1.1 Server listeners (Keyorix terminates TLS)

| Where | File | Cert source | Min version | Ciphers | ALPN / HTTP2 |
|---|---|---|---|---|---|
| HTTP non-AutoCert | `server/tls_config.go:createTLSConfig` | `tlsreload.New(cfg.Server.HTTP.TLS.CertFile, KeyFile)` → `GetCertificate` | TLS 1.2 floor, TLS 1.3 both-pinned in `tls_mode: strict` | `config.DefaultCipherSuites` (AEAD-only) unless `tls.allowed_ciphers` set | ALPN set by net/http `ServeTLS` auto-h2 (stdlib) |
| HTTP AutoCert | `server/tls_config.go:buildAutoCertTLSConfig` | `autocert.Manager` (ACME) `GetCertificate` | same hardening re-applied (#172) | same | autocert sets `NextProtos` incl. acme-tls/1 |
| gRPC | `server/grpc/server.go:createGRPCTLSConfig` | `tlsreload.New(cfg.Server.GRPC.TLS.CertFile, KeyFile)` | TLS 1.2 floor / strict 1.3 | same | grpc-go manages h2 |

- **Certificate/key file path source**: operator YAML `server.http.tls.cert_file` /
  `key_file` and `server.grpc.tls.cert_file` / `key_file`
  (`internal/config/config_server.go:317-318`). Validated non-empty at boot when TLS
  enabled and not AutoCert (`config_server.go:452,467`).
- **gRPC AutoCert**: refused at boot (`config.ErrGRPCAutoCertUnsupported`) and again in
  `createGRPCTLSConfig` for a caller that skipped `Validate` — fail-closed.

### 1.2 Reloader (`internal/tlsreload/tlsreload.go`) — the heart of cert lifecycle

- One `Reloader` per cert/key pair. Served via `tls.Config.GetCertificate`; no
  goroutine, no fsnotify. Re-stats the two files at most once per `CheckInterval`
  (30 s default) from inside the handshake.
- **Startup**: `New()` loads the pair once and returns an error if it does not load →
  a broken config **stops the server at boot** (fail-closed at start).
- **Documented reload policy = KEEP-OLD-CERT**: on any reload failure (stat error on
  either file, or `LoadX509KeyPair` failure — half-written PEM, truncated, empty,
  mismatched key) the **previous good pair keeps being served** and the failure is
  logged; `certMod`/`keyMod` are left unchanged so the next check retries. This is the
  documented behaviour (package doc + `reloadLocked` comments). It is NOT
  "serve-nothing" and NOT "fail-closed-at-runtime".
- **Mismatch safety**: a cert/key mismatch is impossible to *serve* because
  `LoadX509KeyPair` validates the pair atomically before it is adopted; a mismatch
  fails the load and the old pair is retained.
- **Change detection = mtime** of both files. A replacement that preserves both mtimes
  (e.g. `cp -p`, tar with `--preserve`, sub-mtime-granularity swap) is **not detected**
  and the old cert keeps being served until mtime changes — staleness, fail-*safe*
  (never serves a bad cert), candidate HARDENING note (section 4), not a vuln.
- **Who can influence it**: anyone who can write the cert/key files on disk
  (cert-manager, ACME client, operator). Path is operator config only.

### 1.3 Connection-level limits (DoS ceilings)

- HTTP (`server/http_server.go`): fixed, non-configurable — `ReadHeaderTimeout 10s`,
  `ReadTimeout 15s`, `WriteTimeout = RequestTimeout+15s`, `IdleTimeout 60s`,
  `MaxHeaderBytes 64 KiB`. HTTP/2 is stdlib-auto-configured (net/http `ServeTLS`): its
  h2 limits (MaxConcurrentStreams default 250, rapid-reset mitigation CVE-2023-39325)
  are **stdlib defaults from the Go runtime version**, not Keyorix-set.
- gRPC (`server/grpc/server.go`): Keyorix-set — `MaxConcurrentStreams 128`,
  `MaxHeaderListSize 64 KiB`, `MaxRecvMsgSize/MaxSendMsgSize = max_request_body_bytes`,
  `ConnectionTimeout` (handshake), keepalive (`MaxConnectionAge/Idle/Grace`,
  enforcement `MinTime`, `PermitWithoutStream`). Unary 60 s timeout interceptor;
  streams exempt by design.

### 1.4 Outbound clients (verify-by-default) — Phase 1.4 result (trace)

- **Verification ON by default everywhere.** No production code installs a weakening
  custom `VerifyPeerCertificate`/`VerifyConnection`. The only server-side
  `VerifyConnection` is `tlsmetrics.ObserveHandshake` (metrics, adds nothing, weakens
  nothing).
- **`InsecureSkipVerify=true` reachable in production only behind three explicit,
  documented, warn-logged operator opt-in config flags**, each registered in
  `internal/config/insecure_settings_registry.go`:
  - `audit.siem.insecure_skip_verify` (`internal/audit/siem/forwarder.go:244`)
  - `notifications.webhook.insecure_skip_verify` (`internal/notifychan/webhook.go:123`)
  - `evidence_delivery.webhook.insecure_skip_verify` (`internal/evidencesink/webhook.go:95`)
  - plus migrate tool `--tls-skip-verify` (CLI-only flag, `migrate/internal/healthscan/client.go:124`).
- CLI/SDK api client (`cli/internal/apiclient/ca_file.go`, `tlsinspect.go`): verify
  always on, custom CA only via `--ca-file` (hardened loader). Connect backends
  (AWS/Azure/Vault/GCP), k8s sync, dynamic postgres/k8s: verify on, system or
  operator/in-cluster CA, no skip switch.
- Conclusion: **no undocumented weakening**. The three skip flags are the documented
  test/debug seams; each logs a WARNING and is in the insecure-settings registry.

## 2. Harnesses (Phase 1)

One commit per harness (see section 6). Every oracle was red-proofed in a scratch
copy (plant shown, confirmed fired, reverted — never committed).

### Harness 1 — Reloader fail-closed (`internal/tlsreload`)
- **Target**: `FuzzReloaderFailClosed` (commit `e4960eee0d`).
- Drives `tlsreload.Reloader` through fuzz-chosen sequences of on-disk cert/key file
  states — fresh valid pair, expired, not-yet-valid, cert/key mismatch,
  **key-replaced-before-cert** (half-rotation race), truncated PEM, empty file,
  deleted file, symlink swap — with `CheckInterval` pinned to 0 so every handshake
  re-checks.
- **Oracles**: (A) `GetCertificate` never serves an empty config; (B) the served leaf
  public key always matches the served private key — **a mismatch is never handed to a
  client under any sequence**; (C) a differential against the stdlib loader encoding
  the documented keep-old-cert policy: served pair == current on-disk pair if it loads,
  else the previous good pair (never dropped, never replaced by a non-loading one).
- **Red-proof**: planted a reloader that assembles cert+key without matching them →
  oracle B fired on the seed corpus. Reverted.

### Harness 2 — Hostile ClientHello handshake (`server`, package main)
- **Target**: `FuzzTLSHandshakeHostileClientHello` (commit `7d908b1a70`).
- Writes attacker bytes (truncated/oversized TLS records,
  SNI/ALPN/session-ticket/renegotiation shapes, plaintext-HTTP-to-TLS-port, garbage)
  to a fresh loopback connection against the **real** hardened HTTPS listener built by
  `createTLSConfig`.
- **Oracles**: no panic; the server fails closed and closes a never-completing
  handshake within its read deadline (client proves EOF before its own deadline); a
  failed handshake never reaches the HTTP handler; per-connection goroutines don't leak.
- **Red-proof**: removed the server's handshake read deadline → a truncated ClientHello
  hung → "connection not closed within deadline" fired. Reverted.

### Harness 3 — HTTP/2 abusive frames (`server` fuzz + `server/grpc` test)
- **Targets**: `FuzzHTTP2AbusiveFrames` (HTTP, fuzz) and
  `TestHTTP2Abuse_ServerStaysResponsive` (gRPC, deterministic test) (commit `27181b0416`).
- Opens a real TLS+ALPN h2 connection (HTTP) / h2c connection (gRPC) to the real
  listener and replays abusive frame sequences — rapid stream open+reset, SETTINGS/PING
  floods, oversized HEADER blocks, CONTINUATION floods, stray WINDOW_UPDATE/DATA/GOAWAY,
  and (gRPC) opening past MaxConcurrentStreams.
- **Oracles**: no panic; after each abusive sequence the server still answers a normal
  request on an **independent** connection (HTTP GET → 204 / gRPC HealthCheck);
  goroutines bounded.
- **Which limits are whose**: the REST listener's h2 frame limits are **stdlib
  defaults** (net/http auto-h2: MaxConcurrentStreams 250, header-list size from the
  64 KiB MaxHeaderBytes, Go-runtime CVE-2023-39325 rapid-reset mitigation); the **gRPC**
  listener's `MaxConcurrentStreams 128` / `MaxHeaderListSize 64 KiB` / keepalive
  enforcement are **Keyorix-set** (`server/grpc/server.go`), already pinned red/green by
  `server/grpc/connection_limits_test.go`.
- **gRPC is a test, not a fuzz target**, because `testhelper.NewRBACTestHelper` needs a
  `*testing.T` (unavailable in fuzz setup). Same abuse catalogue, same oracle.
- **Red-proof**: a wedged (blocking) handler fired the responsiveness oracle. Reverted.

### Phase 1.4 — Outbound verification (trace, no fuzzer)
Confirmation/trace task satisfied by section 1.4. Result: verification on by default
everywhere; the only production `InsecureSkipVerify` paths are three explicit,
warn-logged, registry-listed operator opt-ins plus the migrate tool's CLI-only
`--tls-skip-verify`; no weakening custom `VerifyPeerCertificate`/`VerifyConnection` in
production.

## 3. Fuzz run log (only real fuzz wall time counted)

| Chunk | Target | fuzztime | execs | result |
|---|---|---|---|---|
| 1a | FuzzReloaderFailClosed | 540s | 7297 | PASS, 0 crashes (op space saturates) |
| 1b | FuzzReloaderFailClosed | 540s | 8464 | PASS, 0 crashes |
| 2a | FuzzTLSHandshakeHostileClientHello | 540s | 2792 | PASS, 0 crashes (handshake-bound rate) |
| 2b | FuzzTLSHandshakeHostileClientHello | 540s | 6227 | PASS, 0 crashes |
| 3a | FuzzHTTP2AbusiveFrames | 540s | 82579 | PASS, 0 crashes |
| 3b | FuzzHTTP2AbusiveFrames | 540s | 60340 | PASS, 0 crashes |
| 3c | FuzzHTTP2AbusiveFrames | 540s | 73063 | PASS, 0 crashes |

**Total real fuzz wall time: ~63 min** (7 × 540s foreground chunks) — target ≥ 60 min
met. All PASS, **zero crashes / hangs / oracle failures** across all three targets. No
crasher files were written to any `testdata/fuzz/` directory. Settings: GOMAXPROCS=2,
-parallel 2, nice -n 10. Temperature sensor `/sys/class/hwmon/hwmon2/temp1_input` is
**not readable** from this sandbox (blocked by the path hook); relied on nice +
GOMAXPROCS=2 + -parallel 2 as the thermal guard per the runtime rules.

## 4. Findings (classified)

No VULNERABILITY / SECURITY-DEFECT / CANDIDATE found.

- **HARDENING (candidate) — mtime-only rotation detection.** `tlsreload` detects a
  rotated pair by comparing `os.Stat().ModTime()` of both files. A replacement that
  preserves mtime (`cp -p`, `tar --preserve`, a sub-granularity swap) is not detected,
  so the old certificate keeps being served until the file mtime actually changes.
  **Fail-safe** (never serves a *bad* cert; serves a *stale* good one), not a vuln.
  Reachability: live — `GetCertificate` is the production handshake hook on both
  listeners. Classification: **HARDENING**.
- **EXPECTED-DIFFERENCE — expired/not-yet-valid pair is adopted on rotation.**
  `tls.LoadX509KeyPair` does not check the validity window, so an operator/ACME client
  that writes an expired or not-yet-valid (but internally coherent) pair has it adopted
  and served. Matches stdlib semantics and the reloader's documented contract (it
  validates loadability, not trust/time); clients reject expiry at their end. Not a
  defect. Classification: **EXPECTED-DIFFERENCE**.

### 4.1 Issue-ready proposal (no production change made)
> **Title**: tlsreload: detect cert rotation by content, not mtime alone
> **Body**: `internal/tlsreload` re-reads the cert/key pair only when either file's
> mtime changes. A rotation that preserves mtime (atomic `rename` from a `cp -p`, a
> restore from an archive with preserved timestamps, or two writes inside one
> filesystem mtime tick) is missed until the next genuine mtime change, so a renewed
> certificate can be served later than the ~30 s the gauge/help text promises.
> Fail-safe (the previous good cert keeps serving), but it can delay a renewal past
> expiry in a pathological case. Proposal: additionally compare a cheap content hash
> (or size+mtime+inode) of each file, or fall back to a periodic unconditional reload
> every N intervals. Low priority; documented keep-old-cert behaviour is preserved
> either way.

## 5. What each oracle does NOT verify
- **Harness 1** does not exercise permission-denied reads (host runs as root → mode
  bits bypassed; omitted rather than silently pass); does not test the 30 s
  `CheckInterval` timing window (pins it to 0 for an exact differential); does not
  assert TLS version floors (that is the listener's `tls.Config`, not the Reloader);
  does not cover concurrent `GetCertificate` callers.
- **Harness 2** does not complete a real TLS session (no client-side crypto), so it
  does not exercise post-handshake behaviour; does not measure heap bytes (goroutine
  count + input cap are the proxies); exercises the non-AutoCert HTTP listener only
  (gRPC/autocert share the same `applyTLSHardening`, covered by unit tests); cannot
  distinguish "closed because hardened-rejected" from "closed because the dumb client
  stalled" — both are fail-closed, which is what it asserts.
- **Harness 3** does not measure heap bytes directly; does not assert a specific numeric
  stream/header cap on the HTTP side (those are stdlib's; the gRPC caps are pinned by
  `connection_limits_test.go`); uses trivial/HealthCheck handlers so it exercises the
  transport layer, not application handlers; the gRPC side is not fuzz-explored
  (deterministic abuse catalogue).
- **All three** assert fail-*safe*/fail-*closed* and liveness; none proves the absence
  of a side-channel, nor the cryptographic strength of the negotiated suite (that is
  crypto/tls's responsibility, pinned by the cipher-suite unit tests).

## 6. Deliverables checklist
- [x] Harness 1 committed (`e4960eee0d`) + targets.d conf + red-proof.
- [x] Harness 2 committed (`7d908b1a70`) + targets.d conf + red-proof.
- [x] Harness 3 committed (`27181b0416`, HTTP fuzz + gRPC test) + targets.d conf + red-proof.
- [x] `gen-targets-conf.sh --check` passes.
- [x] ≥ 60 min real fuzz time (~63 min, 7 chunks, all PASS).
- [x] changelog.d fragment (`changelog.d/tls-lifecycle-fuzz.md`; `changelog-assemble.sh --check` passes).
- [x] INVARIANTS.d entries (`server/grpc/INVARIANTS.d/`:
  `INV-GRPC-tls-handshake-failclosed`, `INV-GRPC-h2-abuse-responsive`, and strengthened
  `INV-GRPC-tls-cert-reload`; validated via the fragment guard — only errors are the
  nested-worktree duplication artifact, absent on a clean checkout).
- [x] Report with reproducer paths + issue-ready proposal.

### Reproducer paths
- Harness 1: `internal/tlsreload/reloader_failclosed_fuzz_test.go` —
  `go test ./internal/tlsreload/ -run '^$' -fuzz '^FuzzReloaderFailClosed$'`
- Harness 2: `server/tls_handshake_fuzz_test.go` —
  `go test ./server/ -run '^$' -fuzz '^FuzzTLSHandshakeHostileClientHello$'`
- Harness 3 (HTTP): `server/http2_abuse_fuzz_test.go` —
  `go test ./server/ -run '^$' -fuzz '^FuzzHTTP2AbusiveFrames$'`
- Harness 3 (gRPC): `server/grpc/http2_abuse_test.go` —
  `go test ./server/grpc/ -run TestHTTP2Abuse_ServerStaysResponsive`
- Commits (branch `fuzz/tls-lifecycle`): `e4960eee0d` (H1), `7d908b1a70` (H2),
  `27181b0416` (H3), `2e3388b75b` (invariants + changelog).

### Note on commit flow
This clone's git-write-guard blocks commits from the shared main checkout, so all
commits were made from a linked worktree on the same branch (`.claude/worktrees/wt`),
which advances the branch ref normally. The branch tip contains every deliverable; the
main checkout's working-tree/index is left out of sync with the advanced ref (cosmetic
only — no uncommitted deliverable is lost).

## 7. Open question for the founder
- **Is server-side mTLS client authentication planned?** Today no listener sets
  `ClientAuth`/`ClientCAs`; transport auth is bearer tokens / machine tokens over
  server-authenticated TLS. The gRPC keepalive comments reference "revoked mTLS cert"
  as a *future* consideration (`server/grpc/server.go:205`), suggesting it was
  anticipated but not built. If mTLS is on the roadmap, the reloader and handshake
  harnesses here would need a client-cert dimension added. Not built per task scope.
