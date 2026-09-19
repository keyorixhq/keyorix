# FINDING: internal/connect backends trust unvalidated response identity/content; two have no response-size bound

**Date**: 2026-09-19
**Found by**: response-side fuzz harness construction/verification for the 4 Connect
backends (`FuzzVaultConnectorResponse`, `FuzzAWSSMConnectorResponse`,
`FuzzAzureKVConnectorResponse`, `FuzzGCPSMConnectorResponse`,
`internal/connect/*_response_fuzz_test.go`), not by a planted assertion catching a
regression — these are pre-existing design gaps, confirmed by direct source reading
and, where noted, by live reproduction against the real backend SDKs.

Status: **not fixed**. Per this campaign's rules, this doc documents and does not
patch. Three independent, related gaps below; recommend a product decision on which
(if any) to close, since each has a different cost/benefit.

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

**Recommendation**: for Azure specifically, either (a) refuse redirects outright the
same way Vault does (`CheckRedirect` returning a refusal), which is almost certainly
correct since Key Vault's real GetSecret API has no legitimate reason to redirect a
GET, or (b) at minimum validate the redirect target isn't
private/link-local (reusing `netutil.IsPrivateOrLinkLocal`, the same predicate
already used elsewhere in this codebase for exactly this class of guard) before
following. (a) is the smaller, more clearly-correct change.

---

## 3. No response-size bound for AWS or Azure; Vault and GCP are bounded (one explicitly, one incidentally)

Requested per-backend report:

| Backend | Size-limited? | Mechanism | Keyorix's own code, or inherited? |
|---|---|---|---|
| Vault | **Yes** | `io.LimitReader(resp.Body, vaultMaxResponseBytes)`, 1 MiB (`vault.go`) | Keyorix's own, explicit |
| AWS Secrets Manager | **No** | `json.NewDecoder(body).Decode(&shape)` streams from `response.Body` directly, no `io.LimitReader` anywhere in the deserializer (`deserializers.go:1059-1066`, confirmed by direct read) | — |
| Azure Key Vault | **No** | `runtime.Payload()` → `io.ReadAll(resp.Body)`, unconditional (`sdk/internal/exported/exported.go:52`, confirmed by direct read) | — |
| GCP Secret Manager | **Yes, but not Keyorix's** | gRPC client-side `MaxRecvMsgSize` default, 4 MiB (`google.golang.org/grpc/clientconn.go:139`, `defaultClientMaxReceiveMessageSize`) | Inherited from grpc-go's own default, not set by Keyorix |

**Not measured**: actual peak allocation under a multi-GB gzip-bomb-shaped response
for AWS/Azure. Both paths (`json.Decoder` streaming; `io.ReadAll`) would, in
principle, allocate proportionally to the DECOMPRESSED size if the underlying HTTP
transport performs transparent gzip decompression (Go's default `http.Transport`
behavior when the caller doesn't set its own `Accept-Encoding`, which neither
`awssm.go` nor `azurekv.go` does) — but this was not empirically measured (no peak-RSS
instrumentation was built) in this round, only the absence of an explicit cap was
confirmed by reading the code. If this is worth closing, measuring the actual
amplification factor first (rather than assuming worst-case) would clarify whether
it is a real DoS risk in practice or a theoretical one bounded by other factors
(connection timeouts, OS-level memory limits on the process).

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
