# ADR-075: Air-gapped OIDC federation

## Status

Proposed.

## Context

ADR-031 built machine-identity OIDC federation (`internal/core/oidc.go`,
`oidc_jwks.go`) and the OIDC half of ADR-063's human SSO
(`buildSSOProviders`, `server/main.go`) on the assumption that Keyorix can
always reach the identity provider's `jwks_uri` (and, for human SSO, its
`/.well-known/openid-configuration` discovery endpoint) live, on every
verification. `docs/air-gap-updates-design.md` states plainly why that
assumption is a problem: "Updates and licensing that work with no internet,
with cryptographic provenance" is a concrete answer regulated buyers
(NIS2/DORA supply-chain integrity, ENS) ask for by name, and air-gapped /
no-egress on-prem is a deployment mode Keyorix already builds for (ADR-062,
ADR-064, ADR-065). Nothing in ADR-031 or the air-gap docs addresses whether
OIDC federation itself survives that mode.

An investigation (findings recorded separately, summarized here) confirmed
it does not, and is worse than a simple omission:

- **Fails closed correctly** when the JWKS endpoint is unreachable — no
  forged-token bypass. Confirmed empirically: a well-formed, correctly-signed
  JWT verified against an unreachable `jwks_uri` returns `context deadline
  exceeded`, wrapped, after the resolver's 10s HTTP client timeout.
- **But every single verification attempt pays that cost.** The JWKS
  resolver's refetch rate limit (`jwksMinRefetchInterval`,
  `oidc_jwks.go:200-213`) only engages once a cache entry exists
  (`entry != nil`). In a deployment where the endpoint is *never* reachable,
  no entry is ever populated, so the guard never activates — every federated
  auth attempt fires a live outbound request and blocks for the full
  timeout, indefinitely.
- **The operator gets no signal pointing at the cause.** The detailed error
  is discarded at `server/middleware/auth.go:817-821`; the caller sees a
  generic `401 Invalid or expired token`, and nothing is logged server-side.
  "Why doesn't federated auth work here" is unanswerable from the running
  system.
- **Human SSO is worse: it doesn't degrade, it disappears.** `buildSSOProviders`
  skips a provider whose discovery fetch fails, "with a warning," so the
  server still boots — but the login option for that provider simply never
  appears. This is a *silent, total* feature loss, not a per-request failure.
- **No ADR or deployment doc acknowledges any of this.** The only mention of
  `oidc_jwks.go` in the air-gap docs cites it as evidence that `ed25519` is
  already vendored — unrelated to whether OIDC federation itself works
  air-gapped. This was an unnoticed gap, not an accepted tradeoff.

**Not this ADR's job to fix:** the error-swallowing at
`middleware/auth.go:817-821` and the `entry != nil` rate-limit gate bug are
real, but orthogonal to air-gap support — they'd be worth fixing even in a
fully-connected deployment. Tracked and fixed separately, not bundled here.

**The seam is already right.** `JWKSResolver` (`oidc.go:41`) is a real
interface; `NewOIDCVerifier` already takes it, not a concrete type. Nothing
about `oidc.go`'s verification logic needs to change. The gap is entirely at
wire-up (`server/main.go:782`, `:1876`) and config
(`internal/config/config.go:479`, `jwks_uri` only) — both of which
unconditionally build a live `HTTPJWKSResolver`. Because `Key(ctx, issuer,
kid)` already takes `issuer` as a parameter, a resolver that serves some
issuers statically and others live is architecturally straightforward — no
interface extraction required. This ADR decides what to build behind that
seam, not whether the seam supports it.

## Two deployment shapes, not one

Collapsing "air-gapped" into a single case is the wrong frame. Two distinct
situations both fall under "no internet egress," and they need materially
different fixes.

**Shape A — enclave with a reachable internal IdP.** No internet egress, but
an internal identity provider (Keycloak, ADFS, Entra ID on-prem/hybrid, or —
for the machine-federation case specifically — the enclave's own Kubernetes
cluster issuer) is reachable within the trust boundary. `jwks_uri` and
`.well-known` discovery both work over the internal network; the only thing
that actually breaks is TLS: the resolver's `http.Client` uses the system
trust store, and an internal IdP's certificate is virtually always signed by
a private/internal CA the system store doesn't carry. This is a trust-store
gap, not a design gap — everything else in the existing code already works
in Shape A.

**Shape B — genuinely disconnected.** No IdP reachable from Keyorix's
network position at all — not "the internet is blocked," but "there is
nothing to call." Requires operator-supplied static key material and an
offline substitute for discovery.

### Shape A is the primary documented path; Shape B is the harder fallback

This has to be argued, not assumed, and the argument rests on what OIDC
federation *is*: a delegation mechanism. Configuring it presupposes an
issuer somewhere the operator trusts and wants to delegate to — if literally
no issuer is reachable from anywhere in the enclave, there is no token
source to federate from in the first place, and the operator would use
ADR-030 opaque machine tokens or ADR-027 PATs instead, neither of which
needs an external IdP at all.

Three concrete reasons Shape A dominates the realistic target deployments:

1. **Regulated buyers with air-gap requirements almost always run their own
   identity infrastructure.** NIS2/DORA/ENS-driven customers (banks,
   critical infrastructure, government) treat federated workload identity as
   baseline security posture, independent of whether *their* network has
   internet egress. "No internet egress" and "no internal IdP" are different
   axes — regulated enterprises overwhelmingly lack the former while having
   the latter.
2. **ADR-031's own primary example is a Shape-A case by construction.** Its
   stated motivating scenario is "a Kubernetes pod gets a short-lived,
   auto-rotated projected service-account JWT," signed by the cluster's own
   issuer. A pod's own cluster API server is reachable from that pod by
   definition — that's how projected service-account tokens and in-cluster
   JWKS resolution work. Shape B only arises for this case if Keyorix's own
   pod is deliberately network-isolated from its cluster's API server (a
   real but narrower hardening choice), or the federated workload is an
   entirely separate on-prem platform (e.g. an internal GitLab CI) — which
   is itself ordinarily Shape A, an internal-but-reachable issuer.
3. **Genuine Shape B is the edge case, not the norm:** fully isolated
   eval/demo environments, a bootstrap window before an internal IdP is
   provisioned, or defense-in-depth network segmentation that isolates
   Keyorix's specific namespace even from other in-cluster traffic.

So: **Shape A (CA-bundle trust) is the flagship supported configuration,
documented as "OIDC federation works air-gapped when your internal IdP is
reachable."** Shape B is built because "completely unavailable" is a worse
outcome than "available via a more manual path," but it is documented as the
fallback for the narrower case, not the headline story.

## Decision 1 (Shape A): per-issuer CA bundle, not a global trust-store change

Add an optional per-issuer CA bundle to both the machine-federation
(`OIDCIssuerConfig`) and human-SSO (`SSOProviderConfig`) config, e.g.:

```yaml
issuers:
  - name: internal-keycloak
    issuer: https://idp.internal.corp/realms/prod
    jwks_uri: https://idp.internal.corp/realms/prod/protocol/openid-connect/certs
    ca_bundle_file: /etc/keyorix/ca/internal-ca.pem   # optional; default: system trust store
    audiences: [keyorix]
```

When set, the issuer's HTTP client (used for both the JWKS fetch and, for
human SSO, the discovery fetch) verifies the IdP's TLS certificate against
that bundle *in addition to* the system store, rather than replacing it —
so a hybrid deployment reaching one on-prem IdP over a private CA and one
public-cloud IdP (e.g. Entra ID via ExpressRoute/private link, still
chaining to a public CA) both work unmodified. Default (no `ca_bundle_file`)
is the system trust store, unchanged from today — purely additive, no
behavior change for existing deployments.

This requires `HTTPJWKSResolver`'s single shared `*http.Client` to become
per-issuer-capable (either a map of clients or a per-issuer `tls.Config`),
and `discoverOIDC` needs the equivalent for the SSO path. Implementation
detail for the follow-up PR, not this ADR.

## Decision 2 (Shape A): client-cert / mTLS to the IdP — deferred

Whether Keyorix should authenticate *itself* to the IdP via a client
certificate (mTLS), rather than just verifying the IdP's server cert, is
explicitly **out of scope for this ADR.**

- JWKS and discovery endpoints are, per the OIDC spec, unauthenticated read
  endpoints — requiring mTLS on them is an unusual IdP hardening choice, not
  the norm. CA-bundle trust alone (Decision 1) already unblocks the
  realistic Shape-A case.
- A client certificate is itself long-lived key material Keyorix would have
  to store and rotate — a secrets-management problem inside the
  secrets-manager, not a trivial addition.
- No current requirement is driving it.

**Reopening trigger:** if a deployment's internal IdP requires mTLS on its
JWKS/discovery endpoints (some hardened enclaves do enforce this), reopen
this ADR to add per-issuer client-cert config alongside the CA bundle.

## Decision 3 (Shape B): static JWKS material via file path

Three options, evaluated against operability, not just feasibility:

- **Inline JWK set in YAML config.** Rejected as the primary path. A JWK is
  base64url-encoded key material inside JSON — legible to nothing, pollutes
  the config file, and ties every key rotation to a config-file edit and
  redeploy. Still supported as a convenience for tests/small deployments,
  but not the documented production path.
- **File path** (operator points config at a local JWKS JSON file). This
  already has a direct precedent in this exact config family: `SAMLProviderConfig`
  supports IdP metadata "inline (`idp_metadata_xml`) or as a file path
  (`idp_metadata_file`)" — same choice, same family, already resolved the
  same way. A file path keeps the config file clean, matches how TLS
  cert/key material is conventionally delivered (file, not inline-PEM-in-YAML),
  and — critically — decouples key rotation from a config redeploy: replacing
  a file is a much smaller, more auditable operational action than editing
  and redeploying structured config.
- **Bundled with the air-gap release artifact** (ADR-064's signed bundle
  import). Rejected. This conflates two independent lifecycles: Keyorix's
  own release cadence and the customer's IdP's key-rotation cadence, which
  is driven entirely by the IdP, not by Keyorix. Forcing a full
  release-bundle cycle every time an operator's IdP rotates a signing key
  would be a severe operability regression — directly the failure mode
  Decision 5's runbook has to avoid.

**Decision: file path is the primary supported mechanism** (`jwks_file` on
the issuer entry), inline JWK-in-config supported only as a secondary/testing
convenience, documented as such.

```yaml
issuers:
  - name: hardened-cluster
    issuer: https://kubernetes.default.svc
    jwks_file: /etc/keyorix/oidc-keys/hardened-cluster.jwks.json   # mutually exclusive with jwks_uri — see Decision 6
    audiences: [keyorix]
```

## Decision 4 (Shape B): reuse ADR-065's trust-registry pattern, adapt the mechanism

ADR-065 (offline license validation) already solved a structurally similar
problem — verifying asymmetric signatures with no network — via a trust
registry of embedded, pinned, purpose-scoped `ed25519` public keys indexed
by `key_id`.

**Reuse the pattern; do not reuse the mechanism, and here's the load-bearing
difference:** ADR-065's keys are *Keyorix's own* keypairs — Keyorix controls
both ends, signs with a private key it holds, and embeds the matching public
key in the release binary at **compile time**, because the key is known and
fixed at build time. A static OIDC JWKS entry pins the *customer's IdP's*
keys — a third party from Keyorix's perspective, chosen and rotated entirely
on the operator's/IdP's own schedule, never known to Keyorix at build or
release time. Compile-time embedding is structurally impossible here; the
keys don't exist yet when Keyorix is built.

So: reuse the **structural pattern** — an explicit, pinned, `key_id`-indexed
table of trusted material, immutable until an explicit operator action
rotates it, distinct from dynamic discovery — via the file-path mechanism
from Decision 3, populated by the **operator at deploy/config time** rather
than by Keyorix at build time. Same shape, different point in the lifecycle
where pinning happens, because the two cases pin different parties' keys.

## Decision 5 (Shape B): offline equivalent of `discoverOIDC()`

`discoverOIDC` (`server/main.go:1710`) fetches
`/.well-known/openid-configuration` to learn `authorization_endpoint`,
`token_endpoint`, and `jwks_uri` — only relevant to human SSO
(`SSOProviderConfig`), since machine federation never does a browser
auth-code redirect and doesn't need those first two endpoints.

Per the OIDC spec, discovery is a convenience, not a requirement — the same
metadata may be configured statically. Add an optional static block to
`SSOProviderConfig`, mirroring the existing `Type`/`SAML *SAMLProviderConfig`
branch pattern already used to select between OIDC and SAML:

```yaml
- name: okta
  type: oidc
  issuer: https://idp.internal.corp/oidc
  static_endpoints:                 # when set, discoverOIDC() is skipped entirely
    authorization_endpoint: https://idp.internal.corp/oidc/authorize
    token_endpoint: https://idp.internal.corp/oidc/token
    jwks_file: /etc/keyorix/oidc-keys/okta-sso.jwks.json
```

When `static_endpoints` is present, `buildSSOProviders` must not call
`discoverOIDC` for that provider at all — not "try discovery, fall back to
static" (that would reintroduce exactly the boot-time network dependency
Shape B exists to remove), but skip discovery outright when static
configuration is present for that provider.

## Decision 6 (cross-cutting): static and `jwks_uri` are mutually exclusive per issuer, enforced at startup

`Key(ctx, issuer, kid)` already takes `issuer`, so mixing Shape A and Shape
B **across different issuers** in one deployment is straightforward and
desirable (e.g. one reachable internal Keycloak plus one hardened cluster
issuer needing static pinning, in the same install).

**For the *same* issuer entry having both `jwks_uri` and `jwks_file`/static
material configured simultaneously: forbidden, fail loud at startup.**
Config validation rejects it rather than picking one silently. Two reasons,
both weightier than the convenience of a fallback:

- This matches the codebase's existing convention of failing loud on
  structurally ambiguous config (`NewOIDCVerifier` already rejects an issuer
  with no audiences at build time; `discoverOIDC` already rejects a
  discovery document whose issuer doesn't match).
- The failure mode of silently preferring one is specifically bad *for this
  feature*: an operator who believes they migrated an issuer to static mode
  but left `jwks_uri` in place, with the system quietly still calling out on
  that path, has an undetected air-gap violation — a compliance-relevant
  outcome (NIS2/DORA/ENS audits can specifically ask "does this system ever
  attempt outbound connections"), not merely an availability bug. Fail loud
  at boot is the only answer that can't produce a silent "yes" to that
  question.

## Decision 7 (cross-cutting): TTL / stale-grace / fail-closed semantics do not apply to static material

The live resolver's `jwksCacheTTL`, `jwksStaleGrace`, and refetch-on-unknown-kid
logic exist to bound trust in a *fetched* value that could go stale or be
served from a compromised/rotated-out source while unreachable. None of that
reasoning applies to static material: there is nothing to refetch, so a TTL
on pinned material would only manufacture a scheduled outage with no
corresponding security benefit — the operator already controls exactly when
the material changes, via the rotation action in Decision 8, not via a
timer.

**Decision: static-mode `Key()` performs zero outbound requests, ever, and
never expires the loaded material — it is valid until explicitly replaced
and reloaded.** This is also the strongest possible answer to an air-gap
compliance question for issuers in static mode: not "resilient to network
failure" but "structurally incapable of attempting egress." It also
sidesteps the `entry != nil` rate-limit gate bug entirely for static
issuers, without needing to touch that (separately tracked) bug — a static
resolver's `Key()` never reaches the fetch path at all.

## Decision 8 (cross-cutting): per-issuer structural property, not a global deployment-mode flag

**No new "air-gap mode" flag.** Whether an issuer is Shape A or Shape B is
determined structurally, by which field is populated on that issuer's config
entry (`jwks_uri` XOR `jwks_file`/static block — see Decision 6), the same
way `SSOProviderConfig.Type` ("oidc" vs "saml") already selects behavior
per-entry rather than via a global "all providers are SAML" setting.

Two reasons beyond matching precedent:

- A global flag forecloses the realistic mixed deployment (Decision 6) —
  one reachable internal IdP plus one hardened-cluster issuer needing static
  pinning cannot both be expressed if "air-gap mode" is an all-or-nothing
  switch.
- A separate mode flag creates a second place that can disagree with the
  actual field configuration (flag says air-gapped, an issuer entry still
  has `jwks_uri` populated — which wins?), reintroducing exactly the
  ambiguity Decision 6 forbids. Making the shape a pure function of which
  fields are populated removes that class of contradiction structurally.

**On the standing "no runtime crypto algorithm selection" principle:** this
does not apply here and is worth saying explicitly rather than silently
skipping. That principle is about not exposing a knob that weakens
cryptographic *strength* (e.g. letting an admin choose HMAC over RSA, or
disable signature verification). Choosing where key material comes from —
network fetch vs. local file — does not touch algorithm choice, key-size
bounds (`minRSABits`/`maxRSABits`), or any verification step; both paths
verify the identical signature with the identical strength requirements.
This is a key-*source* decision, not a key-*strength* decision, and the
principle doesn't constrain it.

## Decision 9 (cross-cutting): audit event design — what makes rotation reconstructable

Today, `Verify()` returns `(issuer, subject, err)` — the `kid` that actually
verified the token is resolved internally and then discarded, never reaching
the machine-identity federation audit event. This is true for the existing
live-fetch path too, not just static mode, but it is what makes "which
key_id verified which token, and when material changed" unanswerable today,
and the user asked this ADR to decide it. In scope for this ADR (unlike the
two explicitly-excluded bugs) because it's a design decision the feature
needs, not an unrelated pre-existing defect.

Keyorix can only audit what happens **inside its own process** — it has no
visibility into when an operator edits a file on disk, only into when that
file was last *loaded*. Two distinct events, both necessary, together making
rotation reconstructable after the fact:

1. **Boot-time load event** (`oidc.static_keys.loaded`, system actor, one
   per issuer configured with static material): records the issuer, the set
   of `key_id`s loaded, a content hash of the file (so "did this file change
   between two boots" is verifiable without diffing file contents directly),
   and the timestamp. This is Keyorix's honest answer to "when did material
   change" — boot-relative, not edit-relative, because edit-time visibility
   is structurally unavailable to a process that doesn't own the file.
2. **Per-verification usage** — extend the existing machine-identity
   federation audit event (already fired on successful auth per ADR-030's
   `actor_type = machine_identity` path) with the `key_id` that verified the
   token and a `key_source` ∈ `{static, fetched}`. Requires `Verify()` to
   return `kid` alongside `(issuer, subject)`.

Together: (1) says what was trusted and when it was loaded; (2) says which
of those trusted keys was actually used, and how often, until it stops
appearing in usage — which is the operational signal that a rotated-out key
has actually fallen out of use.

## Decision 10 (human SSO): boot stays resilient, but silent-skip gets a visible signal

Current behavior — a human SSO provider whose discovery fails is skipped
with a log line, and the server still boots — is **kept for boot
resilience**, not changed to a hard startup failure. One misconfigured or
transiently-unreachable provider must not take down every login path,
including the other (working) SSO providers, PATs, and passwords. This
matches the codebase's existing split between failing loud on structurally
invalid config (bad credential-delivery mode, bad WebAuthn RP config) and
degrading gracefully on runtime/network conditions — discovery failure is
the latter category.

**But a log line alone is the wrong signal for this specific case, and that
does change.** In Shape B, an unreachable discovery endpoint is not
transient — it will never succeed without a config change, so "warning,
continuing" framing is actively misleading, and nobody reliably tails
startup logs. Once Decision 5 ships, a correctly-configured Shape-B provider
uses `static_endpoints` and never attempts discovery at all — so this gap
only bites (a) a provider that *should* have used static config but wasn't
set up correctly, or (b) a genuinely transient Shape-A outage. Both deserve
better visibility than a log line an operator has to know to go looking for
at the exact moment of a restart.

**Decision: keep the resilient boot behavior, but surface skipped providers
as a degraded-state signal on an existing admin-facing posture surface**
(the codebase already has deployment-posture/compliance-snapshot surfaces —
extend one of those rather than inventing a new health-check mechanism),
not merely a startup log line. Exact wiring is implementation detail for the
follow-up PR.

## Non-goals

- Hot-reload of static JWKS material without a restart. Every other OIDC/SSO
  config change in this codebase already requires a restart to take effect
  (wired once at `server/main.go` startup); this ADR matches that existing
  convention rather than introducing file-watching and safe hot-swap under
  concurrent verification as a new, higher-risk mechanism. Key rotation is a
  deliberate, infrequent, planned event — a restart is an acceptable cost
  for it, unlike for something that changes many times a day.
- Client-cert / mTLS to the IdP (Decision 2 — deferred with a reopening
  trigger).
- Fixing `middleware/auth.go:817-821`'s error-swallowing or the `entry !=
  nil` rate-limit gate bug — real, but orthogonal, tracked separately.
- Any change to `oidc.go`'s verification logic itself — the seam already
  supports everything this ADR decides.

## Key rotation runbook (Shape B) — the part that decides operability, not just correctness

1. The IdP administrator rotates a signing key (routine rotation, or
   emergency rotation after suspected compromise) and exports the new
   public JWK(s) from the IdP's own admin console or JWKS endpoint — from
   *outside* Keyorix's air-gapped boundary, where the IdP itself typically
   lives in genuine Shape B, or trivially in-boundary in Shape-A-adjacent
   hybrid cases.
2. The updated JWKS file is transferred into the enclave via the operator's
   existing approved one-way transfer process — the same kind of channel
   ADR-062/064 already assumes exists for getting *anything* into an
   air-gapped environment, carrying a different payload, not the same
   release-bundle lifecycle (Decision 3 explicitly rejects coupling the two).
3. The operator decides whether to retain the outgoing key's `key_id` in the
   file (grace period, so in-flight tokens signed before rotation still
   verify) or drop it immediately (compromise-driven emergency revocation —
   the same rotation-as-revocation property ADR-031's stale-cache hardening
   already protects on the live-fetch path).
4. The operator places the file at the configured path and restarts the
   server (Non-goals: no hot-reload in v1).
5. The boot-time load event (Decision 9.1) records the new `key_id` set and
   file hash. Per-verification usage events (Decision 9.2) show the outgoing
   `key_id` disappearing from live usage going forward — the operational
   confirmation that rotation actually took effect.

This is deliberately more manual than the live-fetch path — that is the
honest cost of Shape B, not a gap in the design. What makes it *operable*
rather than theoretical is that every step maps to something the operator
already does for other air-gapped material (out-of-band transfer, explicit
file placement, a restart, an audit trail) rather than requiring new
infrastructure invented for this feature alone.

## Consequences

- Shape A ships first and is the documented flagship path: "OIDC federation
  works air-gapped when your internal IdP is reachable," gated only on the
  CA-bundle work (Decision 1). This is additive and default-off — no
  behavior change for any existing deployment.
- Shape B ships as the fallback for genuinely disconnected issuers, reusing
  the config-file precedent already established by `SAMLProviderConfig` and
  the trust-registry *pattern* (not mechanism) already established by
  ADR-065.
- Static-mode issuers gain a strictly stronger air-gap property than
  live-fetch issuers ever can: zero outbound requests, structurally, not
  just "resilient to failure of" outbound requests.
- The mutual-exclusivity rule (Decision 6) means a misconfigured issuer
  fails at startup, loudly, rather than producing an undetected partial
  air-gap violation — consistent with this codebase's existing fail-loud
  posture on structural config errors.
- `Verify()`'s signature changes (adds `kid` to its return) to support
  Decision 9 — a small, contained change to an already-narrow, well-tested
  function, not a redesign.
- Human SSO's discovery-skip behavior (Decision 10) requires a posture-surface
  addition; exact surface TBD in implementation, but the decision — resilient
  boot, visible degraded state, not a log line — is made here.
- Two known, real bugs (error-swallowing, rate-limit gate) remain unfixed by
  this ADR on purpose, tracked as separate, smaller, independently-shippable
  changes.
