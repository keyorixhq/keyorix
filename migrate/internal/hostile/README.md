# migrate/internal/hostile

Record-and-mutate hostile-backend fuzzing for connectors that consume data from
external systems. Rules, oracles and planted-defect table: [RULES.md](RULES.md)
(pre-registered; read it before changing an oracle).

> **Provenance.** These files are copied verbatim from the root module's
> `internal/fuzzutil/hostile` (PR #4032, hostile-backend record-and-mutate
> harness). The `keyorix-migrate` tool is a separate Go module
> (`github.com/keyorixhq/keyorix/migrate`) and cannot import the root module's
> internal packages, so the harness is vendored here rather than imported. Keep
> the two copies in sync by hand; the nine planted-defect self-tests
> (`selftest_test.go`) prove the copy still catches every defect class.

## Pieces

| file | what |
|------|------|
| `jtree.go` | order-preserving JSON tree (keeps duplicate keys, can hold raw invalid text) |
| `program.go` | `Decode(bytes) Program`, `Encode`, structure-aware JSON mutators, wire-level options. Every byte string is a valid program, the empty one is the pristine control |
| `server.go` | `Harness`: local httptest backend serving a VALID response per `Route`, a sentinel "internal address" server, framing/encoding/redirect/fault injection, per-request `Served` records |
| `run.go` | `Run` (deadline, hang, panic, allocation, canary), `Finish` (goroutine/FD leak, request ceiling, redirect/SSRF-ish, reporting), `KX_HOSTILE_ALLOW` |
| `selftest_test.go` | nine planted-defect toy clients plus a control; run `go test ./internal/fuzzutil/hostile/` |

## Writing a target

1. Write the valid response per endpoint (`hostile.Route`), taken from the
   backend's documented wire format.
2. Write a STRICT decoder from that documentation (not from the connector).
3. In `f.Fuzz`, `Decode` the bytes, `hostile.New`, call the connector inside
   `h.Run`, assert liveness for the pristine program, and on success compare
   the connector's result with the strict decoder using `h.Delivery`/`h.Intact`.
   End with `h.Finish(t.Fatalf)`.
4. Add `scripts/fuzzing/targets.d/<pkg-slug>__<FuzzName>.conf` and run
   `scripts/fuzzing/gen-targets-conf.sh`.

## Running

    go test ./internal/connect -run '^$' -fuzz '^FuzzVaultHostileBackend$' -fuzztime 10m -parallel 1

`KX_HOSTILE_ALLOW=O5/some-tag,O9/other` suppresses (and prints as
`HOSTILE-KNOWN`) violation classes that were already triaged, so the native
fuzzer, which stops at the first failure, can keep exploring. Use it only for
classes recorded in the findings log.

Synthetic data and local servers only. Never point a target at a real
endpoint or put a real credential in a `Config`.
