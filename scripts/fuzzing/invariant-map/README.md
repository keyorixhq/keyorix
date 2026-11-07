# invariant-map

Maps every named invariant (`INV-*`) to the checks that reference it, so that
"which invariants have a fuzz target, which only a unit test, which nothing" is a
query rather than a reading exercise. Deterministic, offline, standard library
only: no network, no models, no timestamps in the output. Safe in CI and in an
air-gapped checkout.

## Run

From the repository root:

```sh
go run ./scripts/fuzzing/invariant-map                      # one-line summary
go run ./scripts/fuzzing/invariant-map -json map.json -md map.md
go run ./scripts/fuzzing/invariant-map -check               # CI mode, exit 1 on problems
go test ./scripts/fuzzing/invariant-map/                    # unit tests + the repo check
```

Flags: `-root` (default: nearest parent with `go.mod`), `-json`, `-md`, `-check`,
`-allowlist` (default `allowlist.txt` next to the sources), `-no-stale`,
`-strict-docs`. Write reports outside the repository if they are not meant to be
committed.

## What it reads

Definitions (one ID per bullet, `- **INV-X-NN** rule. Why: ... Guard: ...`):

- `<pkg>/INVARIANTS.md` (legacy bullets) and `<pkg>/INVARIANTS.d/*.md` (fragments),
  see `docs/invariants-fragments.md`. Area is the package directory; the section
  is the nearest `##` heading (or the fragment's `<!-- section: -->`).
- `docs/INVARIANTS.md` is read only to compare its per-package counts with the
  parsed docs.

Checks (a mention of an ID in any of these, or a check the doc's own `Guard:`
text names and that exists):

| Where the ID appears | Counts as |
|---|---|
| inside a `func FuzzXxx` (body or doc comment) | fuzz, strong |
| `scripts/fuzzing/targets.d/*.conf` or `targets.conf` comment above a target | fuzz, strong |
| a `fuzzutil` or `*oracle*` Go file | fuzz, strong |
| a helper/top-level comment in a `_test.go` file that also declares a Fuzz func | fuzz, file level only |
| inside a `func TestXxx`, other `_test.go` code, scripts, CI yml, `*.test.ts(x)`, e2e, ledger `.tsv` | test |
| `Guard:` names an existing `TestXxx`/`FuzzXxx`/`BenchmarkXxx` or an existing file | test (fuzz for `FuzzXxx`) |
| production Go source, markdown prose | not a check (only used to detect undefined IDs) |

A fuzz function that is not listed in `targets.d` is flagged `fuzz-unregistered`.
Also read: `docs/adr-conformance-enforced.tsv` and `docs/security-closures.d/*.tsv`
(ledger rows whose proving test no longer exists are reported).

## Classes

- `COVERED-BY-FUZZ`: a fuzz target or oracle names the invariant
  (`fuzz_strength` says whether it is the target itself or only its file).
- `COVERED-BY-TEST`: only non-fuzz checks.
- `DOC-ONLY`: no existing check. An invariant whose only documented check has
  been deleted is DOC-ONLY and also carries `stale_checks`.

Other findings: documented checks that no longer exist, IDs referenced but not
defined (with the closest defined ID as a rename/typo hint), duplicate IDs, IDs
whose prefix does not match their package, near-duplicate IDs, and per-package
count differences against `docs/INVARIANTS.md`.

`severity` / `security_score` order the report; they come from an explicit
`Severity: low|medium|high|critical` line in the entry if present, otherwise from
a fixed keyword table in `score.go` (area weight plus keywords). It is a sort
key, not a risk assessment.

## `-check`

Fails (exit 1) when:

1. code mentions an ID that no doc defines (typo, rename, stale comment);
2. an invariant has no check reference, no `Guard:` text and no `UNGUARDED`
   marker, i.e. a new invariant was added without saying anything about its check;
3. an invariant's `Guard:` names a test or file that no longer exists
   (skip with `-no-stale`).

`-strict-docs` also fails on undefined IDs mentioned only in docs.

Exceptions go in `allowlist.txt`, one rule per line, `#` comments allowed:

```
unknown-ref INV-PKG-*        # placeholder IDs used by tests
no-check    INV-FOO-bar      # reason
stale-check INV-FOO-baz      # reason
```

`-check` is a manual tool for now: `go test ./scripts/fuzzing/invariant-map/`
runs only the fixture tests and does not check the real tree. Run
`go run ./scripts/fuzzing/invariant-map -check` yourself. Making it a blocking
test needs the guard rollout contract (`docs/guard-rollout-contract.md`: a
`guardrules.Rollout(t)` report, a `docs/guard-rollout.d/` row, a
`scripts/guard-meets-open-prs.sh` run) and a `scripts/ci/guard-inputs.d/` row.
Without that row, a docs-only PR would skip the test and could turn main red.

## Tests and fixtures

`testdata/fixture/` is a tiny doc set with planted gaps: a doc-only invariant, an
invariant whose only check was deleted, a duplicate ID, a wrong-prefix ID, a
fuzz-target-covered invariant, a file-level-only fuzz mention, and a code
reference to an undefined ID. The tests assert each one is reported. Its
`INVARIANTS.md` / `INVARIANTS.d` carry a `.fx` suffix on disk (so the repo's own
invariant-doc guard ignores them) and are renamed into a temp dir by the tests.
