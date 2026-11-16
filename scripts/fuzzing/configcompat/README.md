# Config compatibility fuzzer (cross-release)

A differential test and fuzz harness for **upgrade compatibility** of the startup
configuration. Operators upgrade Keyorix by pointing a new release at their existing
config file. A new release must either load that file with the same meaning, or refuse
it with an error that **names** the offending key — fail closed, never silently change a
security posture. This harness takes config files that were valid for earlier releases
and checks them against HEAD.

It **reuses, not copies**, the sibling `configspace` fuzzer and the `internal/config`
package:

- `configspace.LoadModel` / `Model.PostureHolds` / `PostureRule.Explicit` — the posture
  model and its per-predicate opt-in keys.
- the masked-refusal signature idea (`refusal.go`) — a canary typed as a *key* name is
  echoed by design and is not a leak; a canary that leaks as a *value* is.
- `config.DeprecatedSettingAliasPaths()` — the loader's own deprecated-alias table (the
  renamed-key compatibility contract), so the fuzzer can never drift from it.
- `config.InsecureSettingsRegistry` — the code's own enumeration of security-weakening
  settings, used (with the independent posture predicates) as the "security-relevant
  effective values" the differential compares.

## §1 — revs and evidence (why these)

Seeds are the real shipped example configs pulled from old tags, in
`testdata/oldconfigs/` (`<rev>__<file>`). The chosen revs (`Revs` in `seeds.go`):

| Rev | Why |
|---|---|
| `v0.60.0`, `v0.80.0` | old-name era, spread across history |
| `v0.95.3` | **last** release before the ADR-112 `insecure_` rename (#2899) |
| `v0.96.0` | **first** release with the rename + the deprecated-alias table |

`#2899` is contained in `v0.96.0` but not its parent `v0.95.3`; at `v0.95.3` the config
package is a single `config.go` whose YAML tags are the **old** names
(`allow_unsafe_file_permissions`, `keyless_mode`, `allow_insecure_transport`,
`allow_weaker_fallback`, `trust_asserted_email`), and `insecure_settings_aliases.go` does
not exist. So the pair `(v0.95.3, v0.96.0)` brackets the single largest
config-compatibility event this repo has had.

## Invariants (RULES.md)

- **I1** fail-closed load & named refusal.
- **I2** no silently-weakened posture (secure-by-default drift + per-config opt-in).
- **I3** deprecated-alias meaning preserved.

## Running

```
GOMAXPROCS=2 nice -n 10 go test ./scripts/fuzzing/configcompat           # unit tests + seed corpus
GOMAXPROCS=2 nice -n 10 go test ./scripts/fuzzing/configcompat -run FuzzConfigCompat -fuzz FuzzConfigCompat -fuzztime 540s -parallel 2
```

The unit tests need nothing. `TestI3_AllAliasPairsEquivalent` is the real production
guard: every deprecated-alias pair must load, warn by name, and be fingerprint-identical
to its replacement. `TestI2_DefaultPostureMatchesAllowlist` pins the defaults-only posture
set to `default_posture.tsv`.

## Refreshing the old-config corpus

The seed files are committed. To refresh them from a tag:
`git show <tag>:configs/<file> > testdata/oldconfigs/<tag>__<file>`.
