# Keyorix Security Verification & Hardening Evidence

Companion to the [Controls Statement](./NIS2-DORA-ISO-CONTROLS.md). Where that
document maps Keyorix's controls onto NIS2 / DORA / ISO 27001, this one records
the **evidence** that those controls are implemented correctly and stay that way:
the security reviews performed, the issues found and fixed, the surfaces verified
clean, and the automated gates that prevent regression.

> Informational, not a certification. See [`README.md`](./README.md) for the
> positioning disclaimer.

## How controls are verified

Security is verified continuously, not asserted once:

1. **Adversarial subsystem audits.** Each security-critical subsystem is reviewed
   against a concrete threat checklist (authorisation bypass, IDOR, privilege
   escalation, injection, weak crypto, token handling, auth bypass, data
   exposure). Findings are confirmed against the code before action.
2. **Regression tests per fix.** Every security fix lands with a test that fails
   on the vulnerable behaviour and passes on the fix, so the issue cannot
   silently return.
3. **Standing CI gates** run on every change (see below).
4. **Pre-merge review** of authorization- and credential-touching diffs.

## Audit coverage and outcomes

Three subsystem audits have been completed. Coverage and verdict:

| Subsystem | Scope | Verdict |
|-----------|-------|---------|
| **Authentication / cryptography / RBAC core** | Envelope encryption (AES-256-GCM, AAD binding), KEK/DEK management & rotation sweep, session/PAT/machine-token validation, scoped RBAC enforcement | Hardened — see log below; primitives confirmed sound |
| **HTTP API layer** | Every route's authorization guard vs. its handler; per-object access (owner/scope/share); input validation | Hardened — cross-project isolation gaps closed |
| **Token issuance / credential delivery / OIDC federation** | Token entropy & hashing, JWT verifier (alg/aud/iss/exp), machine-token auth, ADR-028 delivery, PAT scope | Clean — one secure-by-default hardening applied |

### Verified-correct properties (evidence of sound design)

The audits confirmed, with code-level tracing, that:

- **Encryption** — all secret material is sealed with AES-256-GCM under a 12-byte
  random nonce per operation, with the secret's identity (`secretID:projectID:
  version`) bound as additional authenticated data so ciphertext cannot be
  transplanted between secrets. KEKs are PBKDF2-derived (600k iterations) and
  wiped after use.
- **Token handling** — every token kind (session, PAT, machine, setup,
  password-reset, impersonation) is minted from `crypto/rand` (256-bit); reusable
  tokens are stored only as SHA-256 hashes and looked up by hash (no plaintext
  comparison, timing-safe by construction); setup/reset links are single-use,
  short-TTL, and purpose-scoped.
- **Federation (OIDC/K8s-JWT)** — the verifier enforces an asymmetric-only
  algorithm allowlist (rejecting `HS*` and `none`, defeating key-confusion), a
  required `exp`, bounded `nbf` skew, an issuer allowlist applied *before* key
  retrieval, and audience intersection. Machine identities bound by `(iss,sub)`.
- **Privilege boundaries** — machine principals receive **no** admin-role bypass;
  a leaked machine token is bounded to its explicit grants. Inactive/suspended
  accounts are rejected on every credential path.

## Hardening log

Issues found by the audits and remediated, by the [control theme](./NIS2-DORA-ISO-CONTROLS.md)
each strengthens:

### Access control & authorisation (§1)

- **Cross-transport authorization parity.** The gRPC surface authorized several
  secret and share operations against the flat (global) permission set while HTTP
  enforced project-scoped permissions. Both transports now enforce identical
  **scoped** RBAC, so a permission held in one project can never act on an object
  in another. *(Severity: medium; closed the full flat-vs-scoped class.)*
- **Cross-project (cross-tenant) isolation.** Five project-nested lifecycle
  routes authorized the caller against the URL's project but then acted on a
  child object belonging to a *different* project (access-request approval,
  membership transition, machine-identity transition, environment restore,
  invitation revoke/resend). Each was a cross-tenant privilege-escalation or
  unauthorized-state-change path; all now reconcile the child's project against
  the authorized project and reject mismatches. *(Severity: up to high.)*

### Authentication & session security (§4)

- **Timely access revocation.** Session validation checked only token expiry, so
  a suspended or deactivated user kept access via existing tokens until expiry.
  Validation now rejects inactive/suspended accounts, and suspension immediately
  purges the user's sessions. *(Severity: high.)*

### Cryptography & protection of data (§2)

- **Key-rotation completeness.** The DEK-rotation re-encryption sweep paginated
  without a stable order, so a rotation could skip rows — leaving some secrets
  under the old key while reporting success. Pagination is now ordered by primary
  key so every row is re-encrypted exactly once. *(Severity: correctness/
  compliance — "rotation complete" is now a guaranteed invariant.)*
- **AAD-downgrade footgun removed.** A dead re-encryption helper stripped the AAD
  binding; removed so it cannot be wired up. *(Severity: low.)*

### ICT third-party risk / federation trust boundary (§5)

- **Signing-key retrieval over TLS.** The OIDC federation resolver accepted an
  `http` `jwks_uri`, which would fetch issuer signing keys over plaintext (a MITM
  could swap keys and forge tokens). `https` is now required (`http` only for
  loopback in development). *(Severity: low; secure-by-default.)*

## Standing CI security gates

Every pull request and merge to `main` runs:

- **`govulncheck`** — fails the build on a known vulnerability in any dependency
  reachable from the code.
- **`gosec`** (medium+) — static analysis for insecure patterns (weak crypto,
  hardcoded credentials, unsafe SQL, etc.).
- **`go test -race`** — the full test suite under the race detector, including the
  security regression tests above.
- **`go vet`**.

## Known, accepted residual risks

Documented tradeoffs, not open defects:

- **Authentication cache window (~30s).** Validated identities are cached briefly
  to absorb request bursts, so a revoked token / suspended account can remain
  valid for up to the cache TTL. Logout and password-change evict immediately;
  the DB session is deleted on suspension. Tighten by reducing the TTL if a use
  case requires sub-minute revocation.
- **Session token storage.** Session tokens are 256-bit random opaque values
  stored for direct lookup; reusable credentials (API/PAT/machine/reset tokens)
  are additionally hashed at rest.

## Change history

This document is updated as further subsystem audits complete (next candidates:
the storage layer and the remote-client path).
