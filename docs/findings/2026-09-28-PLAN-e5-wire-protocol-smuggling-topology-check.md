# PLAN: wire-protocol (request-smuggling) fuzzing, B1/E5 — topology check result: not buildable as scoped

**Status:** investigated, not built. This is a plan/topology-check doc, not a finding — nothing
here is a bug.

## What was asked

SESSION E, item E5: design + first harness for HTTP/1.1 request-smuggling differential fuzzing
"between the chi REST stack and the gRPC-gateway/h2c path (CL/TE conflicts, duplicate headers,
obs-fold, invalid chunk sizes)... in-process only (httptest + raw net.Conn). Oracle: one raw byte
stream is parsed as the same number of requests with the same method/path/body by every hop; any
desync = finding." Explicitly gated: "Plan first in the PR body; only build if a sound oracle
exists."

## What a sound request-smuggling oracle requires

The request-smuggling bug class exists when the SAME raw byte stream is handed to TWO (or more)
HTTP parsers in a chain — a front-end proxy/gateway and a back-end server — that disagree on where
one request ends and the next begins (classically: front-end trusts Content-Length, back-end trusts
Transfer-Encoding, or vice versa). The oracle in the prompt ("parsed as the same number of requests
... by every hop") is only sound if there genuinely ARE multiple hops parsing the same stream. A
single parser, fuzzed against itself, cannot produce a smuggling finding — there's no second party
to disagree with.

## Topology actually checked (not assumed)

Read `server/main.go` end to end for how HTTP and gRPC are wired:

- HTTP (chi REST): `startHTTPServer` (`server/main.go:1688`) builds an `*http.Server` bound to
  `cfg.Server.HTTP.Port` (`server/main.go:1697`), via its own `net.Listen("tcp", server.Addr)`
  (`server/main.go:1720`).
- gRPC: `startGRPCServer` (`server/main.go:1955`) builds a native `grpc.NewServer` bound to
  `cfg.Server.GRPC.Port` on its OWN independent `net.Listen` (`server/main.go:1963`).
- These are two **separate TCP listeners on two separate ports**, started as two independent
  goroutines (`server/main.go:270` and `:295`). Confirmed no shared listener: grepped the whole
  tree for `cmux`, `h2c.NewHandler`, and `grpc-ecosystem/grpc-gateway` (the standard Go libraries
  for either h2c/HTTP-version multiplexing on one port, or REST-to-gRPC transcoding) — zero hits,
  and `grpc-gateway` is not a dependency in `go.mod` at all. There is no `runtime.NewServeMux`
  (grpc-gateway's own mux) anywhere in the tree either.
- Also checked for any internal reverse-proxy hop that would create a genuine two-parser chain
  entirely within this codebase (`net/http/httputil.ReverseProxy`/`NewSingleHostReverseProxy`):
  zero hits in production code.

**Conclusion: "the gRPC-gateway/h2c path" this item's own title describes does not exist in this
codebase.** REST and gRPC are two independently-implemented server stacks, each with its own
listener, its own port, and no relay or transcoding between them. There is no raw byte stream that
both hops ever see. The premise the oracle depends on — two parsers disagreeing about the same
bytes — has no home here.

## What this means for E5

Building the harness as literally scoped (chi vs. gRPC-gateway/h2c differential over one byte
stream) would be building an oracle with nothing to be sound ABOUT: fuzzing chi's HTTP/1.1 parser
against itself via `httptest` + raw `net.Conn` can find real chi/net-http parsing bugs (CL/TE
handling, obs-fold, invalid chunk sizes are all legitimate things to fuzz on their own), but
labeling that "request-smuggling differential" would be asserting a two-hop desync claim with only
one hop actually present — exactly the "asserted, not machine-checked" shape this codebase's own
engineering practices reject, just inverted: the CLAIM the test's name would make (two hops
disagree) could never be true no matter what the fuzzer finds, because there is only ever one hop.
That would be a false-precision test name at best and a permanently-vacuous oracle at worst (green
forever, proving nothing about the thing it's named for).

**Per this item's own gate ("only build if a sound oracle exists"): not building it.** A relay/
gateway topology may exist at DEPLOYMENT time (an operator's own nginx/Envoy/Traefik in front of
either port) — but that is infrastructure outside this repository's code, not something an
in-process Go fuzz harness can exercise, and is out of scope for a first-party fuzzer regardless.

## If a genuinely sound wire-protocol target is wanted here instead

Two adjacent, actually-buildable ideas surfaced while checking this, neither built here (out of
scope for this item — flagging for a future item, not doing it now):

1. **chi's own HTTP/1.1 request-line/header parsing in isolation**, fuzzed as a bounded-work /
   fail-closed target (does a malformed request ever get routed to an unintended handler, panic,
   or hang, rather than being cleanly rejected) — a real, buildable target, just not a "smuggling"
   claim, since there's no second hop to smuggle past.
2. **REST vs. gRPC semantic differential** (not wire-level): for the handful of operations exposed
   on both transports (see `server/faultops`'s op catalog — e.g. `CreateProject` via REST and
   `GRPCCreateProject` via gRPC), fuzz equivalent logical inputs through both and assert the same
   authorization/validation verdict — a sound differential oracle (two independent implementations
   of the same business rule), just answering a different question than wire-level smuggling.

## Verification

No code changed; this is a doc-only PR. `gofmt -l .`: empty (no `.go` files touched).
