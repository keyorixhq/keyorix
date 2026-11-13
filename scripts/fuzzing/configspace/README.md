# Config-space fuzzer

A test and fuzz harness for startup configuration validation. It exercises the YAML
file, the process flags, the secret-source environment variables, deprecated aliases and
defaults of `keyorix-server` as a combinatorial space and checks a fixed set of rules
about it. The rules and their severities are in [RULES.md](RULES.md), registered before the
first run.

## Layout

| File | Purpose |
|---|---|
| `model.yaml` | Machine-readable model: curated options with value classes (valid, boundary, empty, absent, invalid), contradictions, and independent insecure-posture predicates |
| `surface.json` | Generated inventory of every YAML key `config.Config` can decode (checked for drift by `TestSurfaceInventoryUpToDate`) |
| `pairwise.go` | Deterministic all-pairs covering array generator (greedy, seeded) |
| `matrix.go` | Builds the single-fault rows, the covering arrays, and seeded multi-option mutation rows |
| `render.go` | Turns a row into a config file, environment, flags, fixtures and canary secrets |
| `inproc.go`, `targeted.go` | In-process stage: `config.Load` and `Config.Validate`, fidelity, precedence and alias checks |
| `proc.go`, `procchecks.go` | Process stage: starts the real binary, probes it, stops it, scans all output for canary secrets |
| `runner.go` | Orchestration, deduplication, replay (3 times) and minimisation |
| `fuzz_test.go` | Go native fuzz target `FuzzConfigLoadValidate` (registered in `scripts/fuzzing/targets.d`) |
| `planted/` | Planted defects (patches), expectations and `selftest.sh` |

## Stages

1. Single-fault rows: each value of each option alone on the secure baseline.
2. Covering arrays over all non-invalid values: `pair-all` (everything), `pair-clean`
   (values that were accepted alone), `pair-start` (only values that can start in a
   sandbox: SQLite, no KMS/TPM/PostgreSQL).
3. Seeded random multi-option rows (3 to 9 options, a small share of invalid values).
4. Targeted rows: `<NAME>`/`<NAME>_FILE` precedence and the deprecated-alias differential,
   derived from the code's own alias table.
5. Process stage: the real binary on the `pair-start` rows, on every invalid value that
   `Load` accepts, and on samples of the others. Each start uses a temp dir, dynamic loopback
   ports, SQLite and synthetic data, and is stopped with SIGTERM.

## Running

```
go build -o /tmp/keyorix-server ./server
CONFIGSPACE_RUN=1 CONFIGSPACE_BIN=/tmp/keyorix-server CONFIGSPACE_OUT=/private/dir \
  go test ./scripts/fuzzing/configspace -run TestMatrix -v -timeout 3h
```

Results (including candidate details) are written only to `CONFIGSPACE_OUT`
(`findings.jsonl`, `summary.json`, logs). Keep that directory private. `go test` logs
counts only. `CONFIGSPACE_STAGES=inproc` skips the process stage;
`CONFIGSPACE_TEMPLATE` reuses a baseline made earlier. The run is meant to share a busy
machine: set `GOMAXPROCS=2` and run under `nice`.

Unit tests (`go test ./scripts/fuzzing/configspace`) need nothing: they check the model
against `config.Config`, prove the covering arrays cover every pair, and are
deterministic.

## Oracle self-test

```
scripts/fuzzing/configspace/planted/selftest.sh <template-dir> <unpatched-server-binary>
```

Applies each patch in `planted/` (a silently disabled TLS flag, an ignored invalid value,
a secret echoed into the log, a panic on an empty entry, a wrong alias target, an inverted
precedence, a secret in an error message, a suppressed warning) to a scratch worktree and
requires the harness to report it under the expected invariant; the unpatched build must
stay silent for all of them.

## Adding an option

Add it to `model.yaml` with a value of each class that applies. `TestModelPathsExistInConfig`
fails if the path is not a key of `config.Config`. Add a posture predicate in `posture.go`
and a `posture:` entry when the option can weaken the server.
