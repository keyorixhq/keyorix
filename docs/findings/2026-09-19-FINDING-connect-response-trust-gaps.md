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
pagination doesn't apply (§4) and a coverage-replay accounting of the 15 surviving
`internal/connect` mutants against these 4 targets (§5). Recommend a product
decision on which (if any) of §1-3 to close, since each has a different
cost/benefit.

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

## 2. Azure Key Vault connector follows cross-host redirects and blindly trusts the response

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

**Severity: Medium.** Two things raise this above the ref-binding finding's Low: (1)
this requires no backend compromise at all, only a single 3xx response with a
`Location` header — a misconfigured reverse proxy in front of the real Key Vault, or
an open-redirect on the real Key Vault's own infrastructure, is enough; (2) it
reaches an unguarded dial to an attacker-chosen destination, including
`netutil`-classified private/link-local targets (confirmed above), which is exactly
the SSRF shape this codebase already has a standard guard for elsewhere. It stops
short of High because credentials are confirmed not to leak (limiting the blast
radius to response-content trust, not credential theft) and because triggering it
requires the operator's own configured Key Vault endpoint to actually emit a
redirect, which is not the default posture of a healthy, uncompromised Vault.

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

## 5. Surviving `internal/connect` mutants (`killed_by=survived_no_fuzz_coverage`) vs. coverage replay

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
| `awssm.go:80` | off-by-one | `06e35e3b71` | **none** | Inside `awsRefAccountID`, called only when `c.accountID != ""` (`awssm.go:115`) — the fuzz target constructs `NewAWSSecretsManagerConnector(..., "", nil)` (empty accountID), so `awsRefAccountID` is never invoked. Count 0 in all 4. |
| `awssm.go:94` | negate-condition | `e6acac4769` | **none** | Inside `client()`'s real `awsconfig.LoadDefaultConfig` path — same `newClient`-bypass reason as azurekv.go:54. Count 0 in all 4. |
| `awssm.go:94` | comparison-flip | `978638a44c` | **none** | Same line, same reason. |
| `awssm.go:98` | drop-err-guard | `edbf959596` | **none** | Same `client()` real-path region as line 94. Count 0 in all 4. |
| `awssm.go:131` | off-by-one | `c8ede9dcd4` | **`FuzzAWSSMConnectorResponse`** | `if len(out.SecretBinary) > 0` on `GetSecret`'s direct decode path (not gated by `client()`). Seed `{"SecretBinary":"AAEC"}` drives the true branch, `{}` the false branch. Count 1 in the AWS profile, 0 elsewhere. |
| `vault.go:169` | negate-condition | `763e3dabfa` | **none** | `if strings.HasPrefix(safeRef, mountPath)` inside the mount-version *cache-hit* loop (`for mountPath, version := range c.mountVersions`). Each fuzz execution constructs a brand-new `*VaultConnector` (empty `mountVersions`) and calls `GetSecret` exactly once — RULES-mandated "no state carried between execs" — so the cache is always empty and this loop body never runs. Count 0 in all 4, including Vault's own profile. **Structural gap**: reaching this line would require the same connector to serve two reads under the same mount, which this harness's independent-input design deliberately never does. |
| `vault.go:178` | drop-err-guard | `366efeca88` | **`FuzzVaultConnectorResponse`** (statement only) | `if err != nil` after `http.NewRequestWithContext` for the mount-info request. The *statement* executes every call (bundled with lines 176-177 in the coverage profile, count 1 in Vault's profile, 0 in the other 3) — but the guarded error body itself is realistically unreachable by any fuzzed input, since `http.NewRequestWithContext` only errors on a malformed method/URL, and the URL is built from fixed, well-formed components the fuzzer doesn't influence. Coverage-replay says "reached"; the mutant's actual kill condition is a separate question this check doesn't answer. |
| `vault.go:205` | drop-err-guard | `225940c17b` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(body, &mountResp); err != nil` — on the main path of every Vault `GetSecret` call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | negate-condition | `4424845b07` | **`FuzzVaultConnectorResponse`** | `if mountPath == ""` — reached whenever the (always-valid, canned) mount-info response parses successfully, i.e. every Vault call. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:214` | comparison-flip | `de8496a35a` | **`FuzzVaultConnectorResponse`** | Same line. |
| `vault.go:326` | drop-err-guard | `6be5386b63` | **`FuzzVaultConnectorResponse`** | `if err := json.Unmarshal(env.Data, &kv2); err != nil` — the KV v2 unwrap, reached whenever `mountIsV2=true` and the outer envelope parses. Vault's seed corpus includes multiple `mountIsV2=true` cases with valid outer JSON. Count 1 in Vault's profile, 0 elsewhere. |
| `vault.go:329` | off-by-one | `d9bd87e81c` | **`FuzzVaultConnectorResponse`** | `if len(kv2.Data) == 0 \|\| string(kv2.Data) == "null"` — the soft-delete check; Vault's own seed corpus has a dedicated soft-delete seed (`{"data":{"data":null,"metadata":{}}}`) that directly drives the true branch, plus other seeds driving the false branch. Count 1 in Vault's profile, 0 elsewhere. |

**Summary**: 6 of 11 lines (8 of 15 mutants) are reached by `FuzzVaultConnectorResponse`
or `FuzzAWSSMConnectorResponse`; 5 of 11 lines (7 of 15 mutants) are reached by
**none** of the 4 targets, for two distinct structural reasons:

1. **`client()`'s real-SDK-construction path is never exercised** (`azurekv.go:54`,
   `awssm.go:94`, `awssm.go:98` — 6 of the 7 unreached mutants). All 4 targets
   inject a real backend client through the `newClient` test seam specifically to
   get wire-level decode coverage without needing live cloud credentials — the
   necessary tradeoff is that the credential-resolution/client-construction branch
   of `client()` itself (`awsconfig.LoadDefaultConfig`, `azidentity.NewDefaultAzureCredential`,
   `azsecrets.NewClient`) is structurally unreachable through this seam. Closing
   this would need a *different* test (one that lets `newClient` stay nil and
   exercises the real credential chain, closer to what `coverage_test.go`'s
   `TestAWSSM_ClientRealPath_*` / `TestAzureKV_ClientRealPath` already do at the
   unit-test level, not fuzz-level).
2. **`awsRefAccountID` is never called** (`awssm.go:80` — 1 mutant) because the
   fuzz target's connector has no `accountID` configured. This is a fuzz-target
   scoping choice (the account-pin behavior is already covered by
   `TestAWSSM_AccountPin` and friends in `awssm_test.go`), not a structural
   limitation — a variant target configuring a non-empty `accountID` and fuzzing
   ARN-shaped refs could close it, but that's closer to `FuzzConnectRefScoping`'s
   territory (request-side ref parsing) than this round's response-fuzzing scope.
3. **`vault.go:169`'s cache-hit loop needs cross-call state** (1 mutant) that this
   harness's independent-execution design (RULES: "fuzz inputs are independent, no
   state carried between execs") deliberately never provides. Closing this would
   need a dedicated, narrower test that calls `GetSecret` twice on the same
   connector for the same mount — out of scope for response-fuzzing.
