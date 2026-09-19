# FINDING: internal/connect backends trust unvalidated response identity/content; two have no response-size bound

**Date**: 2026-09-19
**Found by**: response-side fuzz harness construction/verification for the 4 Connect
backends (`FuzzVaultConnectorResponse`, `FuzzAWSSMConnectorResponse`,
`FuzzAzureKVConnectorResponse`, `FuzzGCPSMConnectorResponse`,
`internal/connect/*_response_fuzz_test.go`), not by a planted assertion catching a
regression — these are pre-existing design gaps, confirmed by direct source reading
and, where noted, by live reproduction against the real backend SDKs.

Status: **not fixed**. Per this campaign's rules, this doc documents and does not
patch. Three independent, related gaps below (§1-3), plus confirmation that
pagination doesn't apply (§4), a draft (not implemented) of a shared fix for §2/§3
(§5), and a coverage-replay accounting of the 15 surviving `internal/connect`
mutants against these 4 targets (§6). Recommend a product decision on which (if any)
of §1-3 to close, since each has a different cost/benefit.

---

## 1. No ref-binding / response-identity check in any of the 4 connectors

None of the four connectors verify that the value returned in a response actually
belongs to the ref that was requested, even though three of the four backends' own
response shapes carry an identity field that could be checked:

| Backend | Identity field in the real response | Checked against the request? |
|---|---|---|
| Vault | *(none — KV read/write envelope carries no path/name field)* | N/A |
| AWS Secrets Manager | `GetSecretValueOutput.ARN`, `.Name` (`api_op_GetSecretValue.go`) | No — `awssm.go`'s `GetSecret` reads only `SecretString`/`SecretBinary` |
| Azure Key Vault | `Secret.ID` (parses into name+version via `ID.Name()`/`ID.Version()`) | No — `azurekv.go`'s `GetSecret` reads only `Value` |
| GCP Secret Manager | `AccessSecretVersionResponse.Name` | No — `gcpsm.go`'s `GetSecret` reads only `Payload.Data` |

**Why this matters**: the request-response pairing over a single synchronous
HTTP/gRPC call is normally sufficient to bind a response to its request — the gap
only becomes exploitable when something ELSE can make the server answer for a
*different* ref than the one asked (a compromised/misconfigured backend, a
confused-deputy bug on the backend's own side, a caching proxy in front of the
backend, or — see finding 2 below — a followed redirect). None of the four
connectors would notice; the response is trusted as-is and returned to the Keyorix
caller as if it were the requested secret.

**Scope note**: AWS's `account_id` pin and GCP's `project_id` pin (both already
enforced, see `awsRefAccountID`/`gcpRefProjectID`) check the *requested ref's own
ARN/resource-name shape* before the call — a different, already-covered property
("don't even ask for a secret outside my pinned account/project"), not "does the
response's own claimed identity match what I asked for." The two are complementary,
not redundant; this finding is about the latter, which has no coverage at all.

**Recommendation**: not obviously worth adding for AWS/GCP (their pin checks already
bound via a different mechanism) — but worth considering for Azure specifically in
combination with finding 2 below, since Azure is also the one that actively follows
redirects.

**Severity: Low.** This is a defense against *misrouting* (a proxy, cache, or
backend-side bug answering for the wrong ref), not against a *compromised* backend —
a backend that has been compromised outright can simply lie about the identity field
too, so checking it would not have stopped that case. The value of closing this is
narrower than it might first look: it catches accidental misrouting, not malicious
backends.

---

## 2. Azure/AWS connector egress has no SSRF guard at all; redirect is the one path where the destination is attacker-, not operator-, controlled

**SSRF baseline, tested first**: is the *configured* address (`ConnectorConfig.Address`
in `internal/config/config.go`, what an operator's YAML `address:` field sets)
validated against `netutil` — or anything — at registration time or read time?

- **No registration-time check exists for any backend.** Confirmed exhaustively:
  exactly four validators run over `cfg.Connect` (`validateConnectTypes`,
  `validateConnectScopes`, `validateConnectGCPProjectID`,
  `validateConnectAWSAccountID`, all in `internal/config/config.go`) — none touch
  `Address` at all, let alone against a host-classification predicate.
- **AWS has no configurable address in the first place.**
  `server/main.go` constructs the AWS connector as
  `NewAWSSecretsManagerConnector(cn.Name, cn.Region, cn.AccountID, cn.AllowedRefs)`
  — no address/endpoint field, ever. AWS's real endpoint is resolved entirely by
  the AWS SDK's own region-based default resolution
  (`secretsmanager.<region>.amazonaws.com`-shaped, an AWS-owned domain), so "is the
  configured AWS endpoint validated" doesn't apply — there is no configured
  endpoint to validate. (The `BaseEndpoint` override used elsewhere in this repo's
  own test harnesses is a test-only SDK option, not anything `ConnectorConfig`
  exposes.)
- **Vault and Azure both accept a private/link-local `Address` with no error, at
  either construction or read time** — confirmed live, not inferred:
  `NewVaultConnector("x", "http://169.254.169.254:1234", ...)` and
  `NewAzureKeyVaultConnector("x", "https://169.254.169.254:1234", ...)` both
  construct cleanly, and a subsequent `GetSecret` call fails only with an ordinary
  network-level error (`context deadline exceeded` for both, after a real dial
  attempt — Vault's own 15s client timeout, Azure's context-bounded 5s in the
  test), never a validation-rejection message. Azure's plain-`http://` variant
  fails faster, but with `"authorized requests are not permitted for non-TLS
  protected (https) endpoints"` — that's `azcore`'s `checkHTTPSForAuth`, a
  **scheme-only** check with no awareness of which host it is; `https://` to the
  identical private/link-local target sails through it.

**This baseline absence is deliberate, not an oversight, for Vault** —
`validateConnectorURL`'s own doc comment says so explicitly: "Vault connectors are
admin-configured and commonly point at on-prem/private-network instances by
design." An operator-typed `address:` pointing at an internal Vault is the
*primary* legitimate use case for an on-prem product, so guarding the
operator-trusted configuration value itself would be the wrong fix — the
CLAUDE.md-documented reasoning behind `IsLinkLocal` vs. `IsPrivateOrLinkLocal`
(`internal/netutil/dialer.go`) makes exactly this distinction for the JWKS
fetcher's egress already. Azure has no equivalent doc comment, but the same
reasoning applies by construction (Key Vault is also commonly on-prem/private in
this product's deployment shape).

**What follows from this**: there is no "SSRF guard being bypassed by the
redirect" — there is no guard at any point in this egress path, for either
backend. The redirect finding below isn't special because it defeats a check; it's
the **one place the destination comes from an untrusted party (the responding
server) instead of the trusted operator's own configuration** — the same already-
unguarded dial path just receives attacker-chosen input instead of
operator-chosen input. AWS is not part of this reframing in the same way: it has
neither a configurable address (so no baseline case) nor redirect-following
behavior (confirmed in this finding's own §2 body below), so there is no path by
which an untrusted party influences its egress destination at all.

Confirmed by direct, repeated live reproduction (not just source reading) against
the real `azsecrets` client construction path Keyorix's own `azurekv.go` uses:

- A response with status 301, 302, 303, 307, or 308 and a `Location` header pointing
  at a **different host** is followed. This is Go's stdlib default `http.Client`
  redirect policy — `azurekv.go`'s `client()` method builds the SDK client with no
  `CheckRedirect` override, and azcore's own `defaultHTTPClient` doesn't set one
  either (`runtime/transport_default_http_client.go`).
- The credential is **not** leaked to the redirect target: Go's stdlib
  `shouldCopyHeaderOnRedirect` (`net/http/client.go`) strips the `Authorization`
  header on a genuine cross-host hop, confirmed empirically (`attackerAuth=""` in
  the repro below) — this part works correctly.
- The redirected response's content **is** trusted unconditionally: `GetSecret`
  returns the attacker-controlled value with `err == nil`, exactly as if it had come
  from the real Key Vault.

**Repro** (from a version of `azurekv_response_fuzz_test.go` with the redirect
scaffolding — since removed from the merged harness, see below): for a genuinely
cross-host redirect (verified using two different hostname strings, `127.0.0.1` vs
`localhost`, both resolving to the same loopback interface — see the caveat below on
why same-`127.0.0.1`-different-port is *not* a valid cross-host test):

```
code=301 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=302 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=303 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=307 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
code=308 attackerHits=1 attackerAuth="" val="ATTACKER-CONTROLLED" err=<nil>
```

**Methodology caveat, worth recording since it cost real debugging time**: an
earlier version of this repro used two `httptest` servers both naturally bound to
`127.0.0.1` (different ports only) for "origin" and "attacker". Go's own
`shouldCopyHeaderOnRedirect` compares only `url.URL.Hostname()` (port-stripped) to
decide whether a redirect is cross-host for header-stripping purposes — two
same-IP-different-port servers are, to that comparison, the *same host*. That
version of the repro showed the real bearer token reaching "attacker" on every
redirect code, which read as a much worse finding (credential leak) — but it wasn't
real; it was an artifact of an accidentally same-host test. The corrected repro
(renaming the non-TLS attacker's URL to use `"localhost"` instead of its natural
`"127.0.0.1"`, giving Go's comparison a genuinely different hostname string to
compare against origin's `"127.0.0.1"`) shows the credential is NOT leaked, only the
response content is trusted. A `127.0.0.2` second loopback alias would also work but
does not bind without an explicit `ifconfig lo0 alias` on macOS — not portable to a
dev machine, hence the hostname-string substitution instead.

**Why this is not a merged fuzz assertion**: there is no existing host-classification
or response-identity check anywhere in this path to red-proof, and no netutil-style
SSRF dial guard is wired into this connector's transport (unlike the JWKS fetcher,
which does use `netutil.IsLinkLocal` on its dialer). A hard assertion against a
confirmed, currently-true, unaddressed gap would just be a permanently-red test, not
a regression guard — so this was investigated as a one-time, documented
repro rather than left in `internal/connect/azurekv_response_fuzz_test.go`.

**By contrast, AWS does not follow ANY redirect status** via the same connector
construction path (`awssm.go`'s `client()` method, using
`secretsmanager.New(...)` with no custom `HTTPClient`) — confirmed live for both 307
and 308 (`attackerHits=0` in both cases), consistent with
`aws-sdk-go-v2/aws/transport/http.BuildableClient.Do`'s own doc comment: "Redirect
(3xx) responses will not be followed, the HTTP response received will [be] returned
instead." This also held with a bare `&http.Client{}` substituted in (still
`attackerHits=0`), which was not expected going in — the exact mechanism preventing
it even with stdlib defaults wasn't fully traced, but the observed behavior is
consistent and reproducible either way, so this specific property IS asserted as a
hard regression guard in the merged `FuzzAWSSMConnectorResponse` target. Vault
refuses to follow any redirect by explicit design (`CheckRedirect` returns
`http.ErrUseLastResponse`, already merged and tested). GCP is gRPC, not HTTP — no
redirect concept applies.

**Does the connector's transport use `netutil`'s guarded dialer?** No — confirmed by
instrumenting the actual `DialContext` the connector's transport uses (a wrapper
recording every address dialed, not a stand-in), not by reading source and
inferring. Redirected to two targets:

```
target="127.0.0.1:1"        dialed=[<origin>, 127.0.0.1:1]        err="... connect: connection refused"
target="169.254.169.254:80" dialed=[<origin>, 169.254.169.254:80] err="... context deadline exceeded"
```

Both targets were actually dialed (recorded by the spy *before* the real
`net.Dialer.DialContext` ran) — the `127.0.0.1:1` case fails fast with a normal TCP
refusal (nothing listens there), and the `169.254.169.254` case fails only after the
client's own request timeout, consistent with a dial attempt that got no response
(link-local addresses are not specially blocked at the OS/sandbox level here
either). Neither failure comes from a guard rejecting the target *before* dialing —
both are ordinary network-level outcomes. This confirms `azurekv.go`'s connector
does not wire in `netutil.Dialer` (or any other host-classification check) on its
HTTP transport, unlike the JWKS fetcher's `jwksEgressTransport`
(`internal/core/oidc_jwks.go`), which does use `netutil.IsLinkLocal` on its dialer
for exactly this class of guard.

**Severity: Medium** (unchanged from the earlier draft of this finding, but the
reasoning is revised given the baseline result above). It is not "a guard gets
bypassed by the redirect" — confirmed above, there is no guard anywhere in this
path, operator-configured address included, and that absence is *correct* for the
baseline case (on-prem Key Vault addresses are a legitimate, intended target). What
makes the redirect path specifically worth flagging, even though it reuses the
exact same unguarded dial: it's the one point where the destination stops being
something the operator typed into their own config and becomes something an
external, potentially hostile party (whatever answered the request) gets to choose
— reaching `netutil`-classified private/link-local targets (confirmed above) with
zero additional requirement beyond a single 3xx response carrying a `Location`
header (a misconfigured reverse proxy in front of the real Key Vault, or an
open-redirect on the real Key Vault's own infrastructure, is enough). It stops
short of High because credentials are confirmed not to leak (limiting the blast
radius to response-content trust and internal-network reachability, not credential
theft) and because triggering it requires the operator's own configured Key Vault
endpoint to actually emit a redirect, which is not the default posture of a
healthy, uncompromised Vault.

**Recommendation**: for Azure specifically, either (a) refuse redirects outright the
same way Vault does (`CheckRedirect` returning a refusal), which is almost certainly
correct since Key Vault's real GetSecret API has no legitimate reason to redirect a
GET, or (b) at minimum validate the redirect target isn't
private/link-local (reusing `netutil.IsPrivateOrLinkLocal`, the same predicate
already used elsewhere in this codebase for exactly this class of guard, and now
confirmed by live test to be exactly what's missing) before following. (a) is the
smaller, more clearly-correct change.

---

## 3. No response-size bound for AWS or Azure; Vault and GCP are bounded (one explicitly, one incidentally)

Requested per-backend report:

| Backend | Size-limited? | Mechanism | Keyorix's own code, or inherited? |
|---|---|---|---|
| Vault | **Yes** | `io.LimitReader(resp.Body, vaultMaxResponseBytes)`, 1 MiB (`vault.go`) | Keyorix's own, explicit |
| AWS Secrets Manager | **No** | `json.NewDecoder(body).Decode(&shape)` streams from `response.Body` directly, no `io.LimitReader` anywhere in the deserializer (`deserializers.go:1059-1066`, confirmed by direct read) | — |
| Azure Key Vault | **No** | `runtime.Payload()` → `io.ReadAll(resp.Body)`, unconditional (`sdk/internal/exported/exported.go:52`, confirmed by direct read) | — |
| GCP Secret Manager | **Yes, but not Keyorix's** | gRPC client-side `MaxRecvMsgSize` default, 4 MiB (`google.golang.org/grpc/clientconn.go:139`, `defaultClientMaxReceiveMessageSize`) | Inherited from grpc-go's own default, not set by Keyorix |

**Measured** (not inferred): a fake server sending `Content-Encoding: gzip` with a
~2.1 MiB compressed body (a JSON envelope wrapping a ~1 GiB run of a single
repeated byte, ~510:1 compression ratio) against each connector's real client
construction path, peak `runtime.MemStats.HeapAlloc` sampled every 2ms during the
call (a watermark — a spike narrower than the sample interval could be missed —
and delta is measured against a baseline taken immediately before the call, not an
absolute number):

| Backend | `Accept-Encoding` sent | Transparent decompression? | Peak HeapAlloc delta | Elapsed | Result |
|---|---|---|---|---|---|
| AWS Secrets Manager | `gzip` (Go's transport default; SDK sets nothing explicit) | Yes | **~4.09 GiB** | 6.4s | `err=nil`, full ~1 GiB string returned as the secret value |
| Azure Key Vault | `gzip` (same) | Yes | **~3.64 GiB** | 5.9s | `err=nil`, full ~1 GiB string returned as the value |
| Vault (control) | `gzip` (same) | Yes | **~0.9 MiB** | 7ms | `err="secret ... has no data"` — the 1 MiB `io.LimitReader` truncates the read, `json.Unmarshal` fails on the truncated bytes, fails closed |

Confirms both open questions from the earlier (inference-only) version of this
section: (1) neither SDK sets its own `Accept-Encoding`, so Go's `http.Transport`
does add it and transparently decompress — the gzip-bomb shape works exactly as the
threat model describes; (2) the resulting amplification is real and large (~4x the
decompressed size in peak heap, likely accounting for the raw decompressed bytes
buffer plus at least one further copy during JSON decode/UTF-8 validation — not
further decomposed here), not merely theoretical. The Vault control confirms the
inverse just as concretely: the *same* transparent-decompression behavior occurs
(`Accept-Encoding: gzip` is sent, nothing in Vault's connector disables it either),
but the explicit `io.LimitReader` caps what `GetSecret` ever pulls through
`resp.Body.Read()` regardless of how much the underlying gzip reader could produce —
bounding both the memory (~0.9 MiB vs ~4 GiB) and the time (7ms vs ~6s) by roughly
three orders of magnitude, and failing closed rather than returning a
truncated/garbage value.

**Severity: Medium.** A single unauthenticated-adjacent response (the connector
already holds valid credentials to the backend, so this requires the backend itself
to be hostile/compromised/MITM'd, not an anonymous attacker) forces ~4 GiB of heap
allocation and several seconds of latency per request, with no cap — repeated
requests could exhaust available memory on the Keyorix process. Not High because it
requires a hostile backend (not a passive misconfiguration) and the blast radius is
availability (DoS), not confidentiality/integrity.

**Recommendation**: if this is worth closing, Vault's `io.LimitReader` pattern is the
smaller, most obviously-correct model for AWS (wrap `response.Body` before it
reaches `json.NewDecoder`, at the connector's own client construction, not inside
the vendored deserializer) — Azure's `io.ReadAll` is called by azcore's OWN
`runtime.Payload()`, not `azurekv.go`, so bounding it would need a custom
`policy.Transporter` wrapping the response body in a limited reader before azcore's
own decode gets to it, a larger change than AWS's.

---

## 4. Pagination: not applicable

Confirmed by reading all four connectors: each is a single-item read
(`GetSecretValue`, `GetSecret`, `AccessSecretVersion`) with no list/pagination
operation, no next-token/next-link field anywhere in the four files. The
"cyclic/repeating next-token must terminate" oracle class does not apply to any of
the four backends as currently implemented.

---

## 5. Draft fix (NOT implemented — draft only, per campaign rules): one shared hardened `http.Client` for connectors

Sketching the fix §2 and §3 both separately recommended, as one shared piece rather
than two backend-specific patches, since AWS/Azure/Vault all accept *some* shape of
custom `http.Client`/`Transporter` at client-construction time (`awssm.go`'s
`secretsmanager.Options.HTTPClient`, `azurekv.go`'s `azcore.ClientOptions.Transport`,
`vault.go`'s own `*http.Client` field directly). Three components, each targeting a
different gap identified above:

**1. Redirect policy: refuse ALL redirects outright**, matching Vault's existing
`CheckRedirect` (`http.ErrUseLastResponse`) extended to Azure (which currently
follows Go's stdlib default policy, §2) and AWS (which already refuses at the SDK
layer, so this is a no-op for AWS, confirmed in §2). This is recommendation (a) from
§2, not (b) — refuse outright rather than "follow only same-host, non-private"
— since none of these backends' real APIs have any legitimate reason to redirect a
single-secret GET, the simpler policy is also the more clearly correct one (see §2's
own recommendation for why (a) beats (b) here).

**2. Post-decompression body cap, reusing Vault's `io.LimitReader` pattern.**
Requires more than copying Vault's one-liner: Vault caps the RAW wire body because
it never enables transparent decompression in the first place (it never sends
`Accept-Encoding: gzip` — Go's `http.Transport` only auto-decompresses when the
caller hasn't set that header itself, and Vault's connector doesn't). AWS and Azure
DO get transparent decompression (§3's whole gzip-bomb measurement depends on this),
so a cap on the wire bytes wouldn't touch the decompressed size at all — the
`io.LimitReader` has to wrap `resp.Body` in a custom `http.RoundTripper` that runs
*after* the stdlib transport's own gzip unwrapping (i.e., wrap the `Transport`, not
replace it: `rt.Transport.RoundTrip(req)` then `resp.Body =
io.NopCloser(io.LimitReader(resp.Body, cap))` before returning). The cap value
itself is a product decision, not drafted here — Vault's existing
`vaultMaxResponseBytes` (1 MiB) is a reasonable starting point for AWS since a real
Secrets Manager value is capped at 64 KiB by AWS itself; Azure's Key Vault secret
value has no documented AWS-style hard cap, so the right number needs a separate
check against Azure's own documented limits before reuse.

**3. Guarded dialer — flagged here as a genuine open design question, not drafted as
settled.** The obvious move is wiring `netutil.Dialer` (the same predicate the JWKS
fetcher already uses) into the shared client's `DialContext`, rejecting
private/link-local targets unconditionally. **That directly contradicts §2's own
baseline finding**: Vault's `validateConnectorURL` deliberately does NOT reject a
private/link-local *operator-configured* address, because that's the primary
legitimate on-prem deployment shape for this product — and once redirects are
refused outright (component 1 above), the ONLY dial target this shared client ever
reaches, for any of the three backends, IS the operator's own configured address
(AWS has no configurable address at all; Azure's only other destination was the
redirect target, now refused). A netutil-guarded dialer applied uniformly here would
reject the operator's own legitimate Key Vault/Vault address, not just an
attacker-chosen one — it does not distinguish the two, because after component 1
lands there is no longer a second, untrusted destination left for it to guard
against. Concretely: **once redirects are refused outright, a guarded dialer has
nothing left to do that isn't already wrong to do.** This component should be
DROPPED from the fix as literally requested, not implemented as asked — including it
would need either a second, deliberately-different predicate (e.g., only apply the
netutil guard to a hop that is NOT the first one to the connector's own configured
host — meaningless once redirects don't happen) or an explicit product decision to
accept blocking private/link-local operator addresses, which would need its own
separate justification given `validateConnectorURL`'s doc comment already argues the
opposite. Recorded here because the user's own phrasing of this item named it as a
component, and silently omitting it without saying why would be exactly the kind of
unstated scope-narrowing this campaign's rules warn against.

**What flips from report-only to a merged fuzz assertion once (1) and (2) land**
(component 3 intentionally excluded per above):

| Existing report-only item | Becomes assertable how |
|---|---|
| §2's Azure redirect-follows-and-trusts-content gap | `FuzzAzureKVConnectorResponse` gains a redirect-refusal oracle mirroring Vault's oracle (e) — assert `attackerHits == 0` — red-proofed by temporarily reverting the `CheckRedirect` override and confirming the oracle goes red, then reverting the red-proof (never committed), same discipline already used for the 4 merged targets' other oracles. |
| §3's AWS/Azure unbounded-decompression gzip-bomb gap | Both targets gain a bounded-response-size oracle: feed a `Content-Encoding: gzip` response whose decompressed size exceeds the configured cap and assert `GetSecret` fails closed (mirrors Vault's own existing oracle (b) fail-closed check, just with a body that decompresses past the cap instead of being structurally empty) — red-proofed by temporarily removing the `io.LimitReader` wrap. |
| §1's no-ref-binding gap (all 4 backends) | **Unaffected by this fix** — orthogonal problem (response identity vs. transport hardening); would need each backend's own response-identity field (`ARN`/`Name`, `Secret.ID`, `AccessSecretVersionResponse.Name`) checked against the requested ref, not anything in the shared client. |
| §2's baseline (no guard on the operator-CONFIGURED address) | **Deliberately unaffected — stays report-only, on purpose.** This fix only touches the redirect path (now refused outright) and the decompression cap; it does not add, and per the discussion above should not add, any validation of the operator's own configured `Address`. Do not read "component 3 dropped" as this baseline becoming assertable by omission — it remains an explicit, considered non-guard, not a gap this fix closes. |

---

## 6. Surviving `internal/connect` mutants (`killed_by=survived_no_fuzz_coverage`) vs. coverage replay

Source: `~/proj/fuzz-archive/2026-09-19-mutation/connect_mutants.csv`, the 15 rows
with `killed_by == "survived_no_fuzz_coverage"`. Mutants were **not** re-run here
(per instruction — the rig will do that); this is only a coverage-replay check of
whether the 4 new fuzz targets' seed corpora ever *execute* the mutated line at
all, done by generating a per-target `-coverprofile` (`go test -run
'^FuzzX$' -coverpkg=...`, seed corpus only, `-count=1` to force a fresh run) and
checking the exact line's hit count in each of the 4 profiles.

11 distinct file:line locations, one row per mutant (some lines carry more than one
mutant/operator):

| File:Line | Operator | Mutant ID | Reached by | Why |
|---|---|---|---|---|
| `azurekv.go:54` | negate-condition | `cc29006a25` | **none** | Inside `client()`'s real `azsecrets.NewClient` error check — `FuzzAzureKVConnectorResponse` always sets `c.newClient`, so `client()`'s real body (containing this line) is never called at all. Count 0 in all 4 profiles. |
| `azurekv.go:54` | drop-err-guard | `cb9d14f751` | **none** | Same line, same reason. |
| `azurekv.go:54` | comparison-flip | `186a7fad4a` | **none** | Same line, same reason. |
| `awssm.go:80` | off-by-one | `06e35e3b71` | **`FuzzAWSSMConnectorResponse`** (as of the 2026-09-19 harness update below) | Inside `awsRefAccountID`, called only when `c.accountID != ""` (`awssm.go:115`). Originally unreached — the fuzz target constructed `NewAWSSecretsManagerConnector(..., "", nil)` (empty accountID) unconditionally. Now: for ~1/3 of inputs (`status%3==0`, no new fuzz parameter), the harness configures a non-empty `accountID` and passes an ARN-shaped ref instead of the bare name, with a second bit (`(status/3)%2`) choosing whether the ARN's account segment matches or not — both outcomes reach line 80 (the ARN-shape gate at lines 77-79 passes either way; only the value comparison at line 116 differs). Seed corpus alone now confirms it (`status=1200` → matching, `status=1203` → mismatched; both raw values clamp to `code=200` via `clampHTTPStatus`'s remap arithmetic). Count 1 in the AWS profile as of this update, 0 in the other 3 (unchanged). |
| `awssm.go:94` | negate-condition | `e6acac4769` | **none** | Inside `client()`'s real `awsconfig.LoadDefaultConfig` path — same `newClient`-bypass reason as azurekv.go:54. Count 0 in all 4. |
| `awssm.go:94` | comparison-flip | `978638a44c` | **none** | Same line, same reason. |
| `awssm.go:98` | drop-err-guard | `edbf959596` | **none** | Same `client()` real-path region as line 94. Count 0 in all 4. |
| `awssm.go:131` | off-by-one | `c8ede9dcd4` | **`FuzzAWSSMConnectorResponse`** | `if len(out.SecretBinary) > 0` on `GetSecret`'s direct decode path (not gated by `client()`). Seed `{"SecretBinary":"AAEC"}` drives the true branch, `{}` the false branch. Count 1 in the AWS profile, 0 elsewhere. |
| `vault.go:169` | negate-condition | `763e3dabfa` | **`FuzzVaultConnectorResponse`** (as of the 2026-09-19 harness update below) | `if strings.HasPrefix(safeRef, mountPath)` inside the mount-version *cache-hit* loop (`for mountPath, version := range c.mountVersions`). Originally unreached — each fuzz execution constructed a brand-new `*VaultConnector` and called `GetSecret` exactly once, so the cache was always empty. Now: for ~1/3 of inputs (`status%3==0`, no new fuzz parameter), the harness issues a SECOND `GetSecret` on the SAME connector for the SAME ref, guarded off (skipping the strict metamorphic comparison, not the call itself) when the first call's own error came from the mount-info lookup transiently failing rather than the fuzzed response shape — see the harness's own comment for why that specific guard is needed to stay sound under real `-fuzz` concurrency. Seed corpus alone now confirms it (`status=1200`, which also clamps to `code=200`, giving a genuine cache-hit-then-success case). Count 1 in Vault's profile as of this update, 0 in the other 3 (unchanged). |
| `vault.go:178` | drop-err-guard | `366efeca88` | **`FuzzVaultConnectorResponse`** (statement only) | `if err != nil` after `http.NewRequestWithContext` for the mount-info request. The *statement* executes every call (bundled with lines 176-177 in the coverage profile, count 1 in Vault's profile, 0 in the other 3) — but the guarded error body itself is realistically unreachable by any fuzzed input, since `http.NewRequestWithContext` only errors on a malformed method/URL, and the URL is built from fixed, well-formed components the fuzzer doesn't influence. Coverage-replay says "reached"; the mutant's actual kill condition is a separate question this check doesn't answer. |
| `vault.go:205` | drop-err-guard | `225940c17b` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(body, &mountResp); err != nil` — on the main path of every Vault `GetSecret` call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | negate-condition | `4424845b07` | **`FuzzVaultConnectorResponse`** | `if mountPath == ""` — reached whenever the (always-valid, canned) mount-info response parses successfully, i.e. every Vault call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | comparison-flip | `de8496a35a` | **`FuzzVaultConnectorResponse`** | Same line. |
| `vault.go:326` | drop-err-guard | `6be5386b63` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(env.Data, &kv2); err != nil` — the KV v2 unwrap, reached whenever `mountIsV2=true` and the outer envelope parses. Vault's seed corpus includes multiple `mountIsV2=true` cases with valid outer JSON. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:329` | off-by-one | `d9bd87e81c` | **`FuzzVaultConnectorResponse`** | `if len(kv2.Data) == 0 \|\| string(kv2.Data) == "null"` — the soft-delete check; Vault's own seed corpus has a dedicated soft-delete seed (`{"data":{"data":null,"metadata":{}}}`) that directly drives the true branch, plus other seeds driving the false branch. Count 1 in Vault's profile, 0 elsewhere. |

**Summary, updated 2026-09-19 (post-harness-change)**: originally 6 of 11 lines (7 of
15 mutants) were reached by `FuzzVaultConnectorResponse` or
`FuzzAWSSMConnectorResponse`, and 5 of 11 lines (8 of 15 mutants) by **none** of the
4 targets, for two distinct structural reasons enumerated below. (Correcting an
arithmetic slip in this section's earlier draft, which had these two mutant counts
swapped — 7 reached/8 unreached is what the table above actually shows, not 8/7.) A
follow-up harness change (item 2 of the same round that produced the SSRF-baseline
reframing in §2 above) specifically targeted reasons 2 and 3 below, since both were
scoping choices rather than genuine structural limits — **now 8 of 11 lines (9 of 15
mutants) are reached**; only reason 1 (6 of 11 lines, 6 mutants) remains open, and
it stays a genuine structural gap, not a scoping one:

1. **`client()`'s real-SDK-construction path is never exercised** (`azurekv.go:54`,
   `awssm.go:94`, `awssm.go:98` — 6 of the remaining 6 unreached mutants, all 3 of
   the remaining unreached lines). All 4 targets inject a real backend client
   through the `newClient` test seam specifically to get wire-level decode coverage
   without needing live cloud credentials — the necessary tradeoff is that the
   credential-resolution/client-construction branch of `client()` itself
   (`awsconfig.LoadDefaultConfig`, `azidentity.NewDefaultAzureCredential`,
   `azsecrets.NewClient`) is structurally unreachable through this seam. Closing
   this would need a *different* test (one that lets `newClient` stay nil and
   exercises the real credential chain, closer to what `coverage_test.go`'s
   `TestAWSSM_ClientRealPath_*` / `TestAzureKV_ClientRealPath` already do at the
   unit-test level, not fuzz-level). **Not addressed by the harness change below** —
   it's a different kind of gap than reasons 2/3, not just a different backend.
2. **CLOSED, 2026-09-19**: `awsRefAccountID` (`awssm.go:80` — 1 mutant) was never
   called because the fuzz target's connector had no `accountID` configured. Fixed
   by configuring a non-empty `accountID` and an ARN-shaped ref for ~1/3 of inputs
   (see the table row above for the exact mechanism) — this was a fuzz-target
   scoping choice, not a structural limitation, so closing it needed only a harness
   change, no new test.
3. **CLOSED, 2026-09-19**: `vault.go:169`'s cache-hit loop needed cross-call state
   (1 mutant) that a single-`GetSecret`-per-execution harness never provided. Fixed
   by issuing a second `GetSecret` on the same connector for ~1/3 of inputs (see the
   table row above), reusing the same connector instance rather than adding
   genuine cross-execution state — RULES' "fuzz inputs are independent, no state
   carried between execs" is about state persisting ACROSS fuzz executions (e.g. a
   package-level cache surviving between `f.Fuzz` calls), which this does not do;
   the connector and its cache are still constructed fresh inside each execution,
   just exercised twice within that one execution.
