# sdkdiff: cross-SDK differential fuzzer

Runs the same SDK-level scenario through the Go, Node, Python and Java client SDKs of
[`keyorix-sdks`](https://github.com/keyorixhq/keyorix-sdks) against copies of one seeded throwaway
`keyorix-server`, behind a recording reverse proxy, and compares what each SDK put on the wire, what it
returned to its caller and how it classified errors. Rules are fixed in [PREREGISTRATION.md](PREREGISTRATION.md);
the driver line protocol is in [PROTOCOL.md](PROTOCOL.md).

```
scenario (JSON steps) -> driver per SDK -> recording proxy -> fresh server copy (same snapshot for every SDK)
                                              |
                      wire requests + decoded results + error classes -> oracles -> signatures -> minimise -> replay x3
```

Synthetic data only: the server runs on loopback from a temp directory with generated credentials.

## Use

```
scripts/e2e/sdkdiff/build-drivers.sh ../keyorix-sdks build/          # Go driver, Java classes (Node/Python need no build)
go build -o bin/keyorix-server ./server
go build -o bin/sdkdiff ./scripts/e2e/sdkdiff
bin/sdkdiff seed -server bin/keyorix-server -out snapshot             # seeded golden data directory
bin/sdkdiff gen -phase A -out A.jsonl                                 # deterministic edge matrix (phase B: -phase B -from 1 -to 5000)
bin/sdkdiff run -in A.jsonl -sdks go,node,python,java \
   -server bin/keyorix-server -snapshot snapshot -work /tmp/sdkdiff -build build -sdks-dir ../keyorix-sdks \
   -root scripts/e2e/sdkdiff -spec server/http/handlers/openapi.yaml -out out/A
bin/sdkdiff minimize -report out/A/report.json -sig '<text of a signature>' ...   # same flags as run
bin/sdkdiff replay -in minimal.json -sig '<signature>' -n 3 ...
bin/sdkdiff validate -in A.jsonl -baseline out/A/report.json -plants P1,P2,P3,P4,P5,P6,P7 ...   # planted defects
bin/sdkdiff validate -in A.jsonl -sdks go,go@2,node,node@2,python,python@2 -controls ...         # self-pair control
```

Always point `-sdks-dir` at an up-to-date `origin/main` checkout of keyorix-sdks (amendment A7: a first campaign on a
checkout 129 commits behind produced only stale findings). `-shim` (rewrites server JSON keys to the PascalCase
names old SDKs read) is retired for current SDKs and kept only to reproduce pre-A7 runs.

Operation vocabulary: `health`, `login`, `list_secrets` (environment; project fixed to the seeded `alpha`), `get_secret`,
`get_secret_in`, `get_secret_by_ref`, `list_deleted_secrets`, `list_projects`, `create_project`, `list_environments`,
`construct`; Java has no `create_project`, so scenarios that depend on its result diverge for Java by construction.
Limits found while building it: plants only count when they change an observable (A9), and a differential tool
cannot see a defect all four SDKs share.

`run` and `validate` exit non-zero when a batch failed to run, an SDK executed no step (for example a driver that cannot
start), an SDK recorded no wire request (unless every scenario is a `construct` step; A16), a control failed or a plant
was missed or did not run (A14). Oracle X1 flags an `Authorization` header and the login
password or session token in a body sent to the other origin (A12); it does not see a credential in the URL, in another
header, or in an encoded form.

`SDKDIFF_PLANT=P1..P7` (set by `-plant`) switches on a deliberate defect in one driver; it is how the harness proves it can
see a discrepancy. Never set it for a real run.

Unit tests: `go test ./scripts/e2e/sdkdiff` (normalisers, oracles, minimiser helpers, a Go fuzz target for the normalisers).
