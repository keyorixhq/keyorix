# Finding re-fuzz gate (AI-T3)

Patch-validation gate that maps a git diff to KFZ findings whose fuzz targets
cover the changed packages, then replays committed seed-corpus entries and runs
a short fuzz burst for each matched target.

**Script:** `scripts/fuzzing/finding-regate/regate.py`
**Tests:** `scripts/fuzzing/finding-regate/tests/test_regate.py`

---

## Problem

Today a fix for a fuzz finding is reviewed by hand, and nothing in CI
replays the finding's exact reproducer or fuzzes its target when a later PR
touches the same code.  A "fix" that only patches one byte sequence, or a
silent regression of an old fix, is not caught mechanically until the
continuous rig re-finds it — which may take hours or days.

---

## How it works

```
git diff --name-only <range>
     │
     ▼
 changed_packages()
 {"internal/connect", "server/http", ...}
     │
     ▼
 For each active finding in the registry:
   derive (pkg, func) pairs
     ├─ crasher path: crashers/keyorix/<module_enc>/<FuncName>/...
     │                → strip module prefix, replace _ with /
     │                → validate FuncName in targets.d/
     ├─ repro.regression_test: "pkg/path FuzzXxx"
     │                → first token = pkg; Fuzz* words = funcs
     └─ (future) fix_prs changed files via git log
     │
     ▼
 _pkg_matches(changed_pkgs, finding_pkg)
 → matched findings
     │
     ▼
 For each matched finding / target:
   ├─ [replay] go test -run 'FuzzXxx/seedname' ./pkg
   └─ [burst]  go test -fuzz='^FuzzXxx$' -fuzztime=60s ./pkg
     │
     ▼
 Print table; exit 1 on any failure
```

### Path derivation rules

The KFZ registry does not have a dedicated `watched_paths` field.  Paths are
derived at runtime from three sources, tried in this order (highest to lowest
confidence):

1. **Crasher path decoding** (most reliable for findings that have crash
   inputs in the private corpus):
   `crashers/keyorix/<module_enc>/<FuncName>/<hash>` where `<module_enc>` is
   the Go module path with `/` replaced by `_`.  Strip the prefix
   `github.com_keyorixhq_keyorix_`, split on `_` to get the repo-relative
   package path.  `FuncName` is then looked up in `scripts/fuzzing/targets.d/`
   to get the authoritative package path (targets.d wins if the mapping exists).

2. **`repro.regression_test` field**: the first whitespace-separated token
   that looks like a Go package path (`pkg/subpkg/...`).  `Fuzz*` words
   anywhere in the value become the func names.  Private-path values
   (`~/proj/...`) are skipped.

3. **`fix_prs` changed files** (not yet implemented): requires querying git
   log or the GitHub API for the PR's changed files.  Documented here as a
   future enhancement; zero findings are currently mapped via this method.

#### What is NOT mapped today

- **Upstream findings** (scope ≠ first-party, module ≠ keyorix): these have
  no fuzz target in this repo; logged as "skipped — upstream".
- **Hostile-backend findings** (H-001..H-019, F1): the hostile-backend harness
  lives outside `scripts/fuzzing/targets.d/`; those crashers sit under
  `crashers/hostile-backend/` not `crashers/keyorix/`; logged as "no target".
- **Differential and DAST findings** that have no crasher and no parseable
  `regression_test` package path.
- **Findings with only a free-text note** mentioning a package: parsing
  free-form text is fragile and is intentionally NOT done.

### Registry mapping coverage

Measured against the private fuzz-corpus registry (2026-11-18) using the
`derive_finding_targets` function in `regate_lib.py`:

| Scope | Total active | Mapped to ≥1 keyorix path |
|---|---|---|
| first-party (keyorix) | 60 | 28 (47%) |
| — with FuncName (can replay + burst) | — | 14 |
| — package-path only (burst if target found) | — | 14 |
| upstream | 48 | 1 (2%) |
| other (product, third-party) | 12 | 0 |
| **ALL ACTIVE** | **120** | **29 (24%)** |

The 32 unmapped first-party findings are almost entirely hostile-backend,
differential, and review/DAST findings that predate the crasher-path
convention or whose targets live outside this repo.  Six additional findings
have free-text `regression_test` values (e.g. "tests wait until the lock is
observably free") with no parseable package path and no Fuzz* func name —
those are intentionally not parsed (free-text parsing is fragile).

### Seed-corpus replay vs. burst

**Replay** (`go test -run 'FuzzXxx/seedname'`) exercises the specific input
that originally triggered the finding.  This requires that the fix committer
added the reproducer bytes as a committed seed in `testdata/fuzz/<FuncName>/`.
If no seeds are committed for a finding, only the burst runs.

**Burst** (`go test -fuzz='^FuzzXxx$' -fuzztime=60s`) runs the fuzzer for a
bounded window and catches crashes not covered by the existing seed corpus —
including mutations of the original bug.

The burst does NOT replay the private crasher bytes; those stay in the private
corpus and never enter this repository.

### Missing-seed detection

When the tool is invoked with `--registered-seeds <file>` (see the private
CI variant below), the JSON file maps finding IDs to lists of expected seed
files.  If a registered seed file is not present in `testdata/fuzz/`, the gate
fails loudly with `ReproMissingError` rather than silently skipping.  This
catches the case where a fix was merged without committing the regression seed.

---

## Running the gate

```bash
# Against a diff range (merge queue use)
REGATE_REGISTRY=/path/to/fuzz-corpus/registry/findings \
  python3 scripts/fuzzing/finding-regate/regate.py \
    --diff-range origin/main..HEAD

# Against staged changes (developer use)
REGATE_REGISTRY=... \
  python3 scripts/fuzzing/finding-regate/regate.py \
    --staged

# Dry-run: show matched findings without running tests
python3 scripts/fuzzing/finding-regate/regate.py \
  --diff-names internal/connect/connector.go \
  --registry /path/to/registry/findings \
  --dry-run

# Longer burst (use when you have more time)
python3 scripts/fuzzing/finding-regate/regate.py \
  --diff-range HEAD~1..HEAD --fuzztime 120s
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REGATE_REGISTRY` | (required unless `--registry`) | Path to `registry/findings/` |
| `GOMAXPROCS` | `2` (forced by runner) | Concurrency cap |
| `GOCACHE`, `GOMODCACHE`, `TMPDIR` | (not set by the runner) | Taken from the calling environment; go's own defaults apply when unset |

The runner runs `go test` under `nice -n 10` when `nice` is on `PATH` and
without it otherwise.

---

## Two CI variants

### Variant A — Private registry, merge-queue only (RECOMMENDED)

The fuzz-corpus private repository is cloned during the CI run using an
existing deploy key (the rig already uses one).

```
merge queue job "finding-regate":
  1. Clone fuzz-corpus to a temp dir (deploy key, shallow, no history)
  2. python3 scripts/fuzzing/finding-regate/regate.py \
       --diff-range ${{ github.event.merge_group.base_sha }}..${{ github.event.merge_group.head_sha }} \
       --registry $FUZZ_CORPUS_DIR/registry/findings \
       --fuzztime 60s
  3. Gate exits 0 (pass) or 1 (finding regressed) or 2 (config error)
```

**What this enables:**
- Replay of private crasher bytes via `--registered-seeds` (the registered-seeds
  JSON can be generated from the private corpus and passed at runtime — no
  bytes enter the public repo; only file paths are listed).
- Automatic detection of a fix commit that patches only one byte sequence but
  not the underlying class of bug.

**Cost:** Each finding adds ~5 s seed replay + 60 s burst.  For a typical PR
touching 2–3 packages with 2–5 findings each, expect 2–10 extra minutes.
Running only in the merge queue (not on every push) limits the total wall time
added to the merge path.

**Recommendation: use Variant A.**  It is the only variant that can replay
the actual crasher bytes from the private corpus.  The deploy key is already
in use; the extra CI step is a merge-queue-only cost.

### Variant B — Public-safe export, every PR push

A public-safe export is committed to this repo:

```
scripts/fuzzing/finding-regate/public-safe-registry.json
```

It contains: `{finding_id, pkg, func, seed_names}` with NO crasher bytes.
The gate reads this export instead of the private registry.

```
every-pr job "finding-regate-public":
  python3 scripts/fuzzing/finding-regate/regate.py \
    --diff-range origin/main..HEAD \
    --registry scripts/fuzzing/finding-regate/public-safe-registry.json \  # (flag not yet wired; use env)
    --fuzztime 30s
```

**What this provides:**
- Burst check on every PR (no network, no token).
- Seed replay using only committed `testdata/fuzz/` entries.

**What this misses:**
- Private crasher bytes: the specific byte sequences that triggered findings
  are never in `testdata/fuzz/` unless the fix committer added them.
- Findings without committed seeds: only the burst check runs.

**Cost:** 30–60 s burst × number of matched findings per PR push.  For a
busy repo this can add 2–5 minutes to every PR CI run.  This is why
merge-queue-only (Variant A) is recommended: same assurance at a fraction
of the total runner cost.

---

## Expected cost per PR (merge-queue-only, Variant A)

| Scenario | Findings matched | Extra minutes |
|---|---|---|
| Docs-only or unrelated change | 0 | 0 |
| Touches 1 package with 1–2 findings | 1–2 | ~2 |
| Touches 2–3 packages with 3–5 findings each | 3–15 | ~5–15 |
| Large refactor touching many packages | ≤36 (all mapped) | ~40 max |

The 40-minute ceiling assumes every currently-mapped finding fires, 60 s burst
each, plus 5 s replay overhead.  In practice most PRs touch 1–3 packages and
land in the 2–10 minute range.

---

## What this gate does NOT verify

- **Findings fixed in external repos** (upstream, Python SDK, dashdiag):
  no keyorix fuzz target exists for them.
- **Findings without a committed seed**: the burst runs (and may catch a
  regression by chance), but the specific reproducer is not replayed.
- **Burst correctness**: 60 s is not a proof of absence.  A regression that
  requires deep corpus exploration to rediscover will not be caught within
  the burst window.
- **New findings introduced by the PR**: the gate only checks the mapped
  set of _existing_ findings; new bugs introduced are for the continuous
  rig to find, not this gate.
- **The `fix_prs` path derivation**: not implemented.  Findings whose only
  path information comes from the changed files of their fix PR are not mapped.
- **Hostile-backend and differential findings**: their harnesses live
  outside `scripts/fuzzing/targets.d/`; those findings are logged but not run.
- **Burst parallelism**: the burst uses `-parallel=2` (GOMAXPROCS=2) on a
  shared host; two concurrent burst runs may interact with other fuzzer
  sessions running on the same machine.

---

## AI-T3 extension: mutation-kill-rate per file (MUTD-1, not yet implemented)

The backlog item AI-T3-ext calls for checking the mutation-kill rate of the
touched file(s) using `gremlins` as an additional quality signal.

**Current blocker:** `gremlins` does not yet support per-file or per-package
targeting; it currently mutates an entire module.  Running it per-file would
require the MUTD-1 driver (a separate backlog item).

**How to wire it once MUTD-1 lands:**
1. After the burst step, for each changed file, run:
   `gremlins unleash --workdir . --tags fuzz --include <file>` with a
   per-file mutation count cap (e.g. 50 mutations, 30 s each).
2. Report mutation score (killed/total) per file in the gate table.
3. Exit 1 if the score drops below the configured floor (default: 60%).
4. Store results in `.scratch/regate-mutation-<sha>.json` for trend tracking.

No implementation is included here; this section is the hook for MUTD-1.

---

## See also

- `scripts/fuzzing/targets.d/` — per-target fuzz configuration
- `docs/fuzzing/finding-regate.workflow.yml.proposed` — proposed CI workflow
- `fuzz-corpus/registry/README.md` — KFZ record format and fields
- `docs/fuzzing/continuous-rig.md` — the continuous fuzzing infrastructure
