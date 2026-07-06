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
| **Storage / persistence & remote client** | Raw-SQL parameterisation, soft-delete query scoping, tenant filters, migrations, the remote-client TLS trust boundary | Hardened — remote-client TLS made secure-by-default; SQL/scoping/migration surfaces verified clean |

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
  operations against the flat (global) permission set while HTTP enforced
  project-scoped permissions. This was closed for the Secret and Share services
  first, then — in a follow-up audit — for the remaining **Role, User, Audit and
  System** services, which still checked the flat union: a `roles.assign`/
  `users.write` grant held at one project could create global roles, mutate any
  user, or grant roles into another project over gRPC (a cross-project privilege
  escalation), and a project-scoped read permission could read install-wide audit
  logs / user lists. Every gRPC RPC now authorizes through `core.Authorize` at the
  correct scope (global for install-wide ops; the request's project/environment for
  role assignment), identical to HTTP — so a permission held in one project can
  never act on an object in another. *(Severity: medium→high; the full flat-vs-
  scoped class is now closed across all six services.)*
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
- **Remote-client TLS verification secure-by-default.** A `keyorix.yaml` (CLI in
  remote mode) that omitted `tls_verify` resolved to certificate verification
  *off*, exposing the secrets-manager API channel — bearer token and all
  retrieved secrets — to a man-in-the-middle. Verification is now on unless the
  operator explicitly opts out (`tls_verify: false`). *(Severity: high;
  secure-by-default.)*

## Standing CI security gates

11 required status checks gate every pull request and merge to `main` — branch
protection enforces this with no bypass, including for maintainers:

- **`govulncheck`** — fails the build on a known vulnerability in any dependency
  reachable from the code.
- **`gosec`** (medium+) and **`golangci-lint`** — static analysis for insecure
  patterns (weak crypto, hardcoded credentials, unsafe SQL, etc.).
- **`go test -race`** — the full test suite under the race detector, including the
  security regression tests above.
- **`go vet`**.
- **`gitleaks`** — full commit-history secret scan, scoped to the PR's own
  history (not the whole repository's other branches — an earlier version of
  this gate scanned every branch present in the CI runner's git clone, so an
  unrelated secret-shaped string on a completely different in-flight branch
  could fail an unconnected PR; fixed).
- **`CodeQL`** — dataflow/taint-tracking analysis across both Go modules
  (root + the Kubernetes operator), catching cross-function-boundary taint
  flows that pattern-based linters don't model.
- **`checkov`** — Helm chart *security-policy* scanning (non-root, dropped
  capabilities, no privilege escalation, seccomp, RBAC-escalation patterns),
  distinct from the existing `kubeconform` gate, which only validates chart
  *schema* correctness against the Kubernetes API and would not catch a future
  regression like accidentally removing `readOnlyRootFilesystem: true`.
- **`go-licenses`** — Go dependency license compliance for both modules.
  Keyorix is dual-licensed (AGPL-3.0 + commercial); a dependency under an
  actual copyleft or source-available-but-restrictive license (GPL/AGPL/LGPL,
  SSPL, BSL, Commons Clause, Elastic License) could complicate the ability to
  relicense the resulting binary commercially. The allowlist (MIT, Apache-2.0,
  BSD-2/3-Clause, ISC, MPL-2.0) was derived from the actual dependency tree,
  not assumed, and the gate was verified to genuinely fail on an injected
  AGPL-licensed test dependency before shipping.
- **Fuzz-target staleness** — `scripts/fuzzing/targets.conf` (the config for
  the continuous-fuzzing rig, below) must exactly match every real
  `func FuzzXxx` that exists in the tree, in both directions: a target that
  exists but isn't declared would otherwise silently never get fuzzed with no
  signal anything was wrong (an identical hand-maintained list on a sibling
  project missed 18 of 44 real fuzz functions for months before this pattern
  was recognized and guarded against here).
- **DCO sign-off** — every commit needs a `Signed-off-by` trailer matching its
  author (`git commit -s`), certifying the contributor has the right to submit
  the change under the project's license (Developer Certificate of Origin;
  Keyorix uses DCO rather than a full CLA — a deliberate tradeoff given the
  dual-license model, documented in [CONTRIBUTING.md](../../CONTRIBUTING.md)).

## Continuous fuzzing

Native Go fuzzing (`go test -fuzz`, coverage-guided, mutation-based) targets
the codebase's highest-risk parsing/escaping boundaries — chosen by evidence,
not blanket coverage:

- **`FuzzCombineKEK`** (`internal/crypto`) — the Shamir secret-share
  reconstruction path, the exact subsystem behind a genuine cryptographic
  forgery finding (an attacker holding threshold-1 genuine shares could
  previously forge one additional share reconstructing to an attacker-chosen
  KEK; fixed with an HMAC commitment verified outside the interpolated
  payload).
- **`FuzzOIDCVerifierVerify`** (`internal/core`) — JWT parsing for machine-
  identity OIDC federation, the most attacker-exposed token-parsing boundary
  (validated by decoding, not just a DB lookup like session/PAT/machine
  tokens).
- **`FuzzAzureGenerateUpstreamRef`**, **`FuzzPostgresQuoting`**,
  **`FuzzMySQLQuoteString`** (`internal/rotation`) — the rotation-credential
  trust boundary (an admin-configured `rotation_ref` interpolated into a URL
  or hand-rolled SQL escaping), the exact class of bug that already produced
  one real, shipped, fixed path-traversal vulnerability here. `rotation_ref`
  additionally now gets denylist-validated at configuration time (rejecting
  URL/path/SQL metacharacters and control characters) as an earlier, shared
  layer of defense-in-depth ahead of the per-backend checks these fuzz targets
  exercise.
- **`FuzzParse`** (`internal/secrettemplate`) — the hand-rolled byte-index
  parser for `${secret:<ref>}` template placeholder syntax.

Runs continuously (not a scheduled job) on dedicated home-lab infrastructure
separate from CI, rotating through all 6 targets roughly every 14 hours,
re-pulling `main` before each target (this repo's commit velocity — dozens of
merges a day at points — made a once-per-cycle pull leave a target testing
code that was already stale for most of a rotation). A genuine crash
auto-commits its reproducer to a dedicated `fuzz-corpus` branch and triggers
an immediate alert; a daily heartbeat confirms the rig itself is still
running. As of this writing, no crash has been found across any target —
recorded here as a real, verified-clean result, not silence. See
[`scripts/fuzzing/README.md`](../../scripts/fuzzing/README.md) for the full
design and setup.

## Process controls

- **[CODEOWNERS](../../.github/CODEOWNERS)** requires review on
  cryptography/encryption, auth/authz/RBAC core, HTTP/gRPC middleware,
  database migrations, the CI/CD pipeline itself, and this policy.
- **GitHub-native repository security**: secret scanning, push protection
  (blocks a `git push` containing a detected secret before it lands, not just
  scanning after the fact), Dependabot security updates (auto-PRs a
  dependency the moment a CVE is published against the current version), and
  private vulnerability reporting are all enabled.

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

All five security-critical surfaces — authentication/cryptography/RBAC, the HTTP
API, token/credential/OIDC, and storage/remote-client — have now been audited and
hardened.

A subsequent SSDLC hardening pass added the process/pipeline controls
documented above: CodeQL, Helm chart security-policy scanning (`checkov`), Go
dependency license compliance, DCO enforcement, CODEOWNERS, branch protection
with no maintainer bypass, GitHub-native secret scanning/push protection/
Dependabot security updates/private vulnerability reporting, and the
continuous-fuzzing rig (6 targets, clean so far). This document is updated as
further reviews or pipeline changes complete.
