# Design note: post-quantum key exchange on Keyorix TLS (R&D prototype RD-PQTLS-1)

Status: prototype, verified 2026-10-23. Not an accepted ADR; written in ADR shape so it can
become one. User-facing description: [../post-quantum-transport.md](../post-quantum-transport.md).

## Context

Recorded TLS traffic can be stored today and decrypted later if a quantum computer breaks
the key exchange ("harvest now, decrypt later"). Keyorix carries secrets and credentials over
TLS, so the exposure that matters first is the key exchange, not the certificate.

## Decision

Rely on the hybrid group **X25519MLKEM768** that Go's `crypto/tls` offers and prefers by
default (Go 1.24+; Keyorix builds with Go 1.27.3), and do three things around it:

1. **Do not interfere.** No listener or Keyorix-built client sets `CurvePreferences`;
   no image, chart or compose file sets `GODEBUG=tlsmlkem=0`. Tests fail if a listener does.
2. **Prove it on the wire.** Integration tests do real handshakes and assert
   `tls.ConnectionState.CurveID == tls.X25519MLKEM768` for the HTTP listener (default and
   `tls_mode: strict`), the gRPC listener, and the CLI's API client; classical-only and TLS 1.2
   clients must still connect.
3. **Make it observable.** `keyorix_tls_handshakes_total{listener,group}` on the server
   (closed label set) and `key_exchange` / `post_quantum_key_exchange` in `keyorix doctor`'s
   TLS report (additive JSON).

Not decided here: *requiring* the hybrid (see Technical risks).

## New vs state of the art

Honest framing: **the cryptography is not new.** X25519MLKEM768 is the IETF hybrid
(draft-ietf-tls-ecdhe-mlkem) already default in Chrome, Firefox, Cloudflare, AWS, OpenSSL 3.5+
and Go. Keyorix inherits it for free; claiming to have invented or implemented it would be false.

What is specific to Keyorix and has value for an evidence package:

- A secrets manager whose **own listeners, own CLI and own SDKs** negotiate a post-quantum
  key exchange *by default, with no configuration*, and where this is **machine-checked**:
  a regression (a well-meaning `CurvePreferences` hardening, a FIPS-motivated pin) fails CI
  instead of silently dropping the protection.
- A runtime signal (`keyorix_tls_handshakes_total`) that tells an operator what fraction of
  *their* clients is protected, which is the number a security review actually asks for.
- Verified interplay with Go's FIPS 140-3 mode (golang/go#78298): results in the user doc.

What this does **not** claim: post-quantum authentication (certificates and handshake
signatures are classical), post-quantum data at rest, or that every client is protected
(that is a property of the client's TLS library).

## Technical risks

| Risk | Status |
|---|---|
| **Protection depends on the peer.** An old client or a TLS-terminating proxy silently gets a classical exchange. | Mitigated by observability (metric, `doctor`), not by enforcement. Documented. |
| **ClientHello grows by ~1.2 KB.** Old middleboxes that mishandle a multi-segment ClientHello drop the connection. | Real, known in the field. Revert switch `GODEBUG=tlsmlkem=0` documented. Not testable here (no such middlebox). |
| **FIPS mode.** golang/go#78298: `fips140=only` failed every handshake while the hybrid was on the FIPS list. | Fixed upstream (Go 1.27; 1.26 branch). Tested: Go 1.27.2 negotiates the hybrid under `fips140=on` and `only`; X25519-only clients are refused there (by design). Older toolchains would hit the bug. `operator/` declares Go 1.26.6; not tested at the declared minimum. |
| **Go default can change.** The default group list is Go's, not ours; a future Go could reorder or drop the hybrid (e.g. for ML-KEM-1024 or a new hybrid). | The integration tests would go red on a Go upgrade, which is the intended tripwire. |
| **Certificates are still classical.** A quantum adversary active *during* the handshake can impersonate. | Out of scope; stated in the doc. Needs PQ certificates (ML-DSA) in public PKI, not available yet. |
| **Metric counts handshakes, not connections.** Resumed sessions count again; HTTP/2 connections count once. | Stated in the metric help. |
| **Non-Go clients unverified.** Java SDK not run (no JDK in the session); Node 26 / Python 3.14 (OpenSSL 4.0.3) verified by hand, not by CI. | Listed as pending in the doc. |
| **No automated check of Node/Python SDKs.** Their runtimes are outside our build. | A CI job that runs them against a TLS server and reads the server's metric is possible; not built. |

### Proposal (not implemented): `security.require_pq_key_exchange`

Worth considering, with the shape below, **only** once the observed share of classical
clients in real deployments is known (the new metric provides that), because a mistake locks
clients out:

- Per listener, default `false`. When `true`, set `tls.Config.CurvePreferences` to the hybrid
  groups only and `MinVersion` to TLS 1.3 (a TLS 1.2 handshake has no hybrid group).
- It implies TLS 1.3 only (the effect of `tls_mode: strict`), so the two settings must not
  disagree; at start it warns when the process has `GODEBUG=tlsmlkem=0`, which would make
  every handshake fail.
- It would be the first place the repo sets `CurvePreferences`, so the "never sets
  CurvePreferences" test must be replaced by "sets exactly the hybrid set iff the option is on".
- Failure mode to document: a classical client gets a TLS alert `handshake_failure`; the
  `keyorix_tls_handshakes_total` counter does not see refused handshakes, so add a refused
  counter in the same change.
- In FIPS mode, `CurvePreferences = [X25519MLKEM768]` is accepted on Go 1.27.

Recommendation: do not build it yet. The default already gives the protection to every
client that can have it; enforcement only adds lock-out risk until classical share is ~0.

## Evidence

Tests: `server/pq_transport_test.go`, `server/grpc/pq_transport_test.go`,
`internal/tlsmetrics/keyexchange_test.go`, `cli/internal/apiclient/tlsinspect_test.go`.
Manual, against a real `keyorix-server` with TLS: OpenSSL 4.0.3 `s_client` (hybrid by default,
X25519 when forced, TLS 1.2 classical), Node 26.11, Python 3.14 SDK, Go SDK, and the CLI
(`keyorix doctor`): hybrid; macOS system curl 8.7.1 (Apple TLS): X25519. See the report.
