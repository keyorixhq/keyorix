# internal/fuzzutil/hostile

Record-and-mutate hostile-backend fuzzing for connectors that consume data from
external systems. Rules, oracles and planted-defect table: [RULES.md](RULES.md)
(pre-registered; read it before changing an oracle).

## Pieces

| file | what |
|------|------|
| `jtree.go` | order-preserving JSON tree (keeps duplicate keys, can hold raw invalid text) |
| `program.go` | `Decode(bytes) Program`, `Encode`, structure-aware JSON mutators, wire-level options. Every byte string is a valid program, the empty one is the pristine control |
| `server.go` | `Harness`: local httptest backend serving a VALID response per `Route`, a sentinel "internal address" server, framing/encoding/redirect/fault injection, per-request `Served` records |
| `run.go` | `Run` (deadline, hang, panic, allocation, canary), `Finish` (goroutine/FD leak, request ceiling, redirect/SSRF-ish, reporting), `KX_HOSTILE_ALLOW` |
| `known.go` | `Known` (a target's triaged, still-open findings), `Evaluate`, `RequireKnownReproduces` |
| `selftest_test.go` | nine planted-defect toy clients plus a control; run `go test ./internal/fuzzutil/hostile/` |
| `known_selftest_test.go` | the `Known` filter, the no-response replay rule and the body cap, each in both directions |

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

A triaged finding that stays open goes in the target's `Config.Known` list
instead: a stable `ID`, a classification, a `Prefix` as narrow as the finding
allows (plus `ErrContains`/`When` to narrow further), and the minimised
program as `Repro`. Keep the crasher file as a regression seed, and add a
`Test*KnownFindingsReproduce` test that runs each entry's `Repro` without the
entry and calls `hostile.RequireKnownReproduces`. That test goes red when the
finding is fixed; then delete the entry and keep the seed. Every suppressed
hit is printed as `HOSTILE-KNOWN[<id>]`, and any other violation in the same
run still fails.

Synthetic data and local servers only. Never point a target at a real
endpoint or put a real credential in a `Config`.
