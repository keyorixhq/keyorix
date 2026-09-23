# FINDING: FuzzGCPSMConnectorResponse OOM-killed CI via a per-iteration gRPC
# server/client leak (not a memory-size bug); GCP connector's real client path had
# no response-size bound, unlike its AWS/Azure siblings

**Date**: 2026-09-23
**Found by**: investigating PR #2004, where `FuzzGCPSMConnectorResponse` killed the
CI runner twice (exit 143, "runner shutdown") while stalled at 0 execs/s. Not found
by a planted assertion catching a regression — both are pre-existing gaps in the
fuzz harness and the production connector, confirmed by direct measurement and
source reading.

Pre-push review added three checks against the initial fix, folded into their
relevant sections below: (1) the reused fixture's per-input isolation is now a
permanent regression test, not just asserted (§1); (2) production's
per-`GetSecret` client dial was checked for the same leak mechanism and does
not appear to reproduce it, reported but not fixed here (§3); (3) the 1 MiB
receive cap's scope (every RPC the connection carries, not just
`AccessSecretVersion`) and its value versus AWS/Azure's are made explicit (§2).

---

## 1. The CI kill: a per-iteration `grpc.Server`+`bufconn`+client leak, not a
   message-size bug

**Initial hypothesis (from the PR #2004 investigation brief) was wrong, and worth
recording why**: the suspicion was that GCP Secret Manager's client, being gRPC
rather than HTTP, lacked the size-bounded body read that `hardened_client.go`
already gives the AWS/Azure connectors (`connect-response-size-cap-aws-001`/
`-azure-001` below) — i.e., that a large fuzzer-generated payload was ballooning
heap the same way the AWS/Azure gzip-bomb findings did. Reading
`google.golang.org/api/transport/grpc/dial.go`'s `DialPool` directly disproves this
for the harness: `option.WithGRPCConn(conn)` (how the fuzz target injects its fake
client, mirroring how `c.newClient` is overridden for every other connector's
tests) returns `&singleConnPool{o.GRPCConn}, nil` **before any `grpc.DialOption` is
ever applied** — the harness's own client conn (built via a bare `grpc.NewClient`
with no override) keeps grpc-go's real, unmodified 4 MiB client-side receive cap
regardless. Confirmed by direct measurement too: `GODEBUG=gctrace=1` across every
repro run below shows heap staying in the 2–58 MB range even while stalled — no
allocation growth precedes or accompanies the stall.

**What's actually happening**: `FuzzGCPSMConnectorResponse`'s per-iteration body
built a brand-new `bufconn.Listen` + `grpc.NewServer()` + `grpc.NewClient()` +
`secretmanager.Client` on **every single fuzz execution**, then tore all four down
again (`grpcSrv.Stop()`/`conn.Close()`/`lis.Close()`, plus `GetSecret`'s own
`cl.Close()`) before the next one. Under sustained fuzzing (thousands of
executions/sec) this reliably leaked goroutines that `Stop()`/`Close()` never
unblocked: bufconn pipe readers parked in `sync.Cond.Wait` (both the client's
`http2Client.reader` and the server's `http2Server.HandleStreams`), plus orphaned
`loopyWriter`/`keepalive`/`grpcsync.CallbackSerializer` goroutines from both sides
of each torn-down connection. Over enough iterations this degrades throughput to
~0 execs/s and leaks memory continuously — this local Mac's ample RAM turns it into
"high peak RSS, eventually finishes" (matches the 7.9 GB reported at
`-parallel=4`/90s locally); a memory-constrained GitHub Actions runner turns the
same leak into an OOM-kill mid-run.

**Reproduced three independent ways**, isolating the harness/engine boundary:

1. `go test -fuzz=^FuzzGCPSMConnectorResponse$ -parallel=1`, `GODEBUG=gctrace=1`:
   throughput drops to a hard, sustained `0/sec` at varying exec counts (835,
   1325, 1670, 8245, 12215 across separate runs) and never recovers within the
   observed windows (60–120s), while GC essentially stops firing (heap flat,
   2–58 MB) — a hang, not an allocation blowup.
2. Sending `SIGQUIT` to the stalled worker subprocess (found via `ps` — a
   `go test -fuzz` coordinator spawns one child worker process per `-parallel`
   slot) produced `fuzzing process hung or terminated unexpectedly while
   minimizing: EOF` — the coordinator loses its worker entirely, not merely
   slows down.
3. **Decisive**: a standalone `testing.T` loop (`TestGCPSMLoopProbe`, temporary,
   not shipped) drove the exact same per-iteration
   listener+server+client+`GetSecret` body **outside `go test -fuzz`'s
   coordinator/worker RPC machinery entirely** — same continuous slowdown (43ms/iter
   at iteration 0–200 degrading to 80ms/iter by iteration 2600–2800) and a `SIGQUIT`
   goroutine dump at the 3-minute test timeout showing multiple leaked
   `bufconn.(*pipe).Read` goroutines blocked in `sync.Cond.Wait`, confirming the
   leak is in the connector+harness code itself, not an artifact of the fuzzing
   engine's process/pipe protocol.

**Fix**: `internal/connect/gcpsm_response_fuzz_test.go` now builds the fake
server, its `bufconn` listener, and the gRPC client/connection **once per fuzz
worker process**, reused for every input (torn down via `f.Cleanup` only when the
worker exits). `fakeSecretManagerServer`'s response fields are reconfigured
per-iteration under a `sync.RWMutex` (needed because `fuzzutil.Guard` — see its own
doc comment — never cancels a timed-out call's goroutine, so a genuinely-hung prior
iteration could still be reading them). `GetSecret`'s own per-call
create-client/`defer cl.Close()` behavior (real production behavior, worth
continuing to exercise) is preserved via a `reusableGCPClient` wrapper whose
`Close()` no-ops instead of tearing down the shared fixture.

**Verified**: re-running the exact repro commands post-fix shows continuous
progress with no sustained 0/sec window, at both `-parallel=1` (70s+, 8k+ execs,
never froze) and `-parallel=4` (90s, 70,014 execs, peak RSS ~509 MB via
`/usr/bin/time -l` — down from the reported ~7.9 GB at the same settings
pre-fix). Full `go test ./internal/connect/...` still passes.

**Per-input isolation of the shared fixture — checked separately, because reuse
on its own proves nothing about correctness**: removing the per-iteration
teardown only removes what leaked; it says nothing about whether
`setResponse`'s mutex-guarded overwrite actually replaces every field an
earlier input set, or whether a stale in-flight response could race a new one.
Either would make every downstream fuzz oracle unsound — checking the CURRENT
input's expectations against a stale or mixed response, which could mask a
real bypass (a stale error papering over what should have been a genuine
failure) or manufacture a false one (a stale success reported against an input
that should have failed). `TestGCPSMSharedFixture_NoCrossInputLeak`
(`internal/connect/gcpsm_fixture_isolation_test.go`) drives four inputs
back-to-back on the identical shared fixture through `GetSecret` itself (the
same call path the fuzz oracles check) — error → different success → different
error → different success — and asserts each call sees only its own input's
response. Verified both directions matter: temporarily reverting `setResponse`
to skip the field overwrite (keeping only the `hits` reset) makes this test
fail immediately on input 1 (`gcpsm_fixture_isolation_test.go:77`, "expected a
\"not found\" error, got ... has no value" — a zero-value fallthrough, not a
stale value, since the fixture starts zeroed, but it demonstrates the test
detects a broken overwrite); restoring the real implementation makes it pass
again. Included in the PR as a permanent regression test, not a one-off check.

## 2. Production gap (independent, defense-in-depth): the real client path had no
   response-size bound at all

Confirmed by reading the vendored client directly
(`cloud.google.com/go/secretmanager@v1.21.0/apiv1/secret_manager_client.go`'s
`defaultGRPCClientOptions()`): Google's own SDK sets
`grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32))` as a dial
default — effectively no cap (~2 GiB) — unlike the AWS/Azure connectors, whose HTTP
clients already read through `hardened_client.go`'s `sizeCappedRoundTripper`
(`connect-response-size-cap-aws-001`/`-azure-001` below). `gcpsm.go`'s
`client()` fallback (`secretmanager.NewClient(ctx)`, used whenever `c.newClient` is
nil — i.e. every real, non-test call) inherited this uncapped default outright. A
malicious or compromised endpoint (a MITM'd connection, or a compromised
`secretmanager.googleapis.com` peer) could force this process to buffer an
attacker-sized `AccessSecretVersion` response before `GetSecret` ever gets a chance
to reject it.

Not what caused the CI OOM (§1's harness bypasses all dial options via
`option.WithGRPCConn`, so it never exercised this default in either direction) —
found while confirming §1's initial hypothesis, and fixed as a genuine, independent
gap once confirmed real.

**Fix**: `gcpsm.go`'s `client()` fallback now appends
`option.WithGRPCDialOption(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(gcpMaxRecvMsgSize)))`
(`gcpMaxRecvMsgSize = 1 MiB`) after Google's own defaults — grpc-go resolves
repeated `MaxCallRecvMsgSize` call options last-value-wins, so the later, smaller
cap wins. GCP Secret Manager's own documented maximum secret version payload is
64 KiB; 1 MiB leaves generous headroom for protocol/framing overhead while bounding
the worst case to a small, fixed amount instead of ~2 GiB.

**Verified** (`TestGCPSMMaxRecvMsgSize`, `internal/connect/gcpsm_recv_cap_test.go`):
can't be tested through `GetSecret`/`c.newClient` at all — that seam is exactly
`option.WithGRPCConn`, which (per §1) bypasses dial-option processing entirely in
both directions — and `client()`'s real fallback needs ADC this environment
doesn't have. Tested by proving the underlying grpc-go mechanism directly instead:
dial the same way `client()`'s fallback composes its options (append
`grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(N))` onto a `DialOptions` list
that already carries Google's own `math.MaxInt32` default) against a fake server
returning a payload between the two caps, using the low-level
`secretmanagerpb.SecretManagerServiceClient` directly (bufconn + insecure creds, no
ADC touched). RED subtest reproduces the pre-fix shape (default alone, no
override) and confirms it really does accept the oversized payload unbounded;
GREEN subtest adds the override and confirms it's rejected with
`codes.ResourceExhausted`.

**Scope — does the cap cover every RPC the connector can make, not just
`AccessSecretVersion`?** `gcpMaxRecvMsgSize` is applied as a
`grpc.WithDefaultCallOptions` **dial** option (`gcpsm.go:107-109`), so it binds
every RPC made over that `*grpc.ClientConn` — not specific to one method. But
the connector's own `gcpSMAccessAPI` interface (`gcpsm.go:51-54`) declares only
`AccessSecretVersion` and `Close()`; `client()`'s return type is
`gcpSMAccessAPI`, not the full `*secretmanager.Client`, so the connector
**cannot call any `List*` method through this seam at all** — not "doesn't
today," but structurally can't without first widening the interface, which
would be a visible, reviewable change. `List*` responses (paginated, and each
page's size scales with the caller-controlled page size) were the concern
worth checking precisely because they're the shape most likely to exceed a
per-secret-sized cap — confirmed inapplicable here, not merely absent from a
grep.

**Comparison with AWS/Azure's cap**: `internal/connect/hardened_client.go:32`
defines `connectMaxResponseBytes = vaultMaxResponseBytes`, and
`internal/connect/vault.go:24` defines `vaultMaxResponseBytes = 1 << 20` — the
same 1 MiB value `gcpMaxRecvMsgSize` uses. Not a coincidence to call out as a
difference: it's the same number for the same reason (GCP's own 64 KiB secret
payload cap and the other backends' comparable single-secret response sizes
both leave the identical amount of headroom at 1 MiB), so all four connectors
now share one consistent response-size ceiling.

## 3. Checked, not fixed: production's per-`GetSecret` client dial — does it
   leak the same way?

`client()`'s fallback dials a brand-new gRPC client/connection on **every**
call — `secretmanager.NewClient(ctx, ...)` at `gcpsm.go:107` — and `client()`
itself is invoked on every single `GetSecret` call (`gcpsm.go:138`, no
memoization on `*GCPSecretManagerConnector`). Unlike the harness's bug, it
**does** close what it opens: `GetSecret`'s `defer func() { _ = cl.Close() }()`
at `gcpsm.go:142` runs after every call. So this is not "dials and never
closes" — it's "dials, calls once, and closes, every single time," which is
structurally the same create/use/teardown shape §1's fix removed from the
fuzz harness.

That similarity is exactly why it needed checking rather than assuming safety
from "it closes it": §1's leak occurred **despite** `Stop()`/`Close()` being
called correctly on every iteration — the leaked goroutines were ones
`Close()` didn't reliably unblock. So the open question was whether that
specific leak mechanism is general to grpc-go's HTTP/2 transport lifecycle
(in which case production, dialing constantly over real TCP/TLS, would be at
risk too) or specific to `bufconn`'s cooperative `sync.Cond`-based pipe
signaling (in which case production's real-socket path would not be).

**Checked by isolating the transport**: reran the identical
create-client/call/close-per-iteration loop (`fakeSecretManagerServer` +
`secretmanagerpb` client, same shape as `client()`'s fallback) 3,000 times
over a **real `127.0.0.1` TCP listener** instead of `bufconn` — still no ADC or
real GCP endpoint touched, only the transport swapped. Result: flat throughput
(no slowdown across the run, ~0.29 ms/iter throughout — contrast §1's bufconn
loop, which degraded from 43 ms/iter to 80 ms/iter over 2,800 iterations and
never finished 30,000 in 3 minutes) and flat goroutine count (2–4 throughout,
ending at 3; contrast §1's leaked, still-blocked `bufconn.(*pipe).Read`
goroutines at timeout). This isolates the leak to `bufconn`'s pipe signaling,
not grpc-go's transport lifecycle in general — a real TCP `Close()` unblocks
readers immediately at the OS level, where `bufconn`'s `sync.Cond`-based
`Read()` apparently does not always get signaled promptly on `Stop()`/`Close()`.

**Verdict: does not appear to reproduce the harness's leak mechanism** under
this test (plain TCP + insecure creds; real TLS wasn't separately isolated,
though a `tls.Conn.Close()` closes its underlying `net.Conn` the same way and
isn't expected to differ). Not fixed or further investigated here, per scope —
this section is a report, not a closure.

**Separate, lower-severity observation, also not fixed here**: dialing a full
new gRPC/TLS connection to `secretmanager.googleapis.com` for every single
`GetSecret` call (rather than caching a connector-lifetime client) is a real
efficiency cost — a TLS handshake and connection setup on every secret read —
independent of whether it leaks. Worth a dedicated follow-up if GCP-backed
secret read volume ever becomes latency- or connection-count-sensitive; out of
scope for this PR.

---

## Status

Both fixed on branch `fix/gcpsm-fuzz-memory`. Not merged — local commits only,
pending review. No product/scope decision needed; both are mechanical fixes with
red/green proof.
