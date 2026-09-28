# Continuous-fuzzing rig: pve01 setup (design + scripts)

> **STEP 1 ONLY — design, scripts, no long runs.** Per the FUZZ-RIG coordinator note
> (2026-09-27): "STEP 1 (design, scripts, no long runs) is GO. STEP 2 (build + 1-hour
> smoke on pve01) is HOLD: PHASE0 Part A is still running in CT 240, and a second fuzz
> load would corrupt its measurements." Nothing in this document has been run on pve01.
> Andrei starts STEP 2 after PHASE0 signals "GO STEP 2" — see `~/proj/prompts/inbox/FUZZ-RIG.md`.

## Scope

This is the design for pointing the shared `keyorixhq/fuzz-harness` runner's continuous
rig at this repo's per-target `scripts/fuzzing/targets.d/` layout (C1, this session) and
adding two pieces of rig-level bookkeeping the runner doesn't have today: a per-target
time budget, and a documented harvest/corpus-sync cadence. It does **not** cover the
`fuzz-harness` runner's own source (external repo, no local checkout in this session —
see the HANDOFF below), and it does not run anything on pve01.

## Architecture

```
                     ┌─────────────────────────────┐
                     │  scripts/fuzzing/targets.d/  │  <- per-target fuzztime (C1)
                     │  *.conf  (pkg|Fuzz|duration) │
                     └──────────────┬──────────────┘
                                    │ read directly (post-HANDOFF)
                     ┌──────────────▼──────────────┐
                     │  scripts/fuzzing/targets.d/  │  <- per-target priority (this doc)
                     │  BUDGET.tsv                  │
                     └──────────────┬──────────────┘
                                    │
                     ┌──────────────▼──────────────┐
                     │   fuzz-harness fuzz-runner.sh │  (external repo, pve01)
                     │   - picks next target          │
                     │   - runs `go test -fuzz=X`     │
                     │     for that target's fuzztime │
                     │   - on crash: REPORT_MODE=private│
                     │   - on new coverage: harvest guard│
                     └──────────────┬──────────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 ▼                                      ▼
      keyorixhq/fuzz-corpus                   this repo's testdata/fuzz/
      (crashers, private, never                (only a human-reviewed,
       committed here directly)                 red-proofed seed — see
                                                 "Corpus sync" below)
```

`targets.d/*.conf` (source of truth for **what** to fuzz and **how long** one invocation
runs) and `targets.d/BUDGET.tsv` (source of truth for **how often**, relative to other
targets, within one rig cycle) are two separate, orthogonal files by design: retuning a
target's per-invocation fuzztime (e.g. because a parsing dependency changed and reopened
coverage) never requires touching its priority, and re-prioritizing a target ahead of a
security review never requires touching its fuzztime.

## HANDOFF this design assumes (not done here — external repo)

`scripts/fuzzing/targets.d/README.md` (C1) already has the exact handoff: point
`fuzz-harness`'s target-discovery step at `scripts/fuzzing/targets.d/*.conf` directly
instead of the generated `scripts/fuzzing/targets.conf`. This document's "read
`targets.d`" architecture line assumes that handoff has landed; until it has, the rig
keeps reading the generated `targets.conf` exactly as it does today, unaffected by
anything in this repo beyond what C1 already produces. Not re-derived here — see that
README for the concrete steps.

## Per-target budget (`scripts/fuzzing/targets.d/BUDGET.tsv`)

A new file, orthogonal to each target's own `.conf` fuzztime. Format: one line per
target file (same `<pkg-slug>__<FuzzName>` stem `targets.d/*.conf` uses), tab-separated:

```
<pkg-slug>__<FuzzName>	<priority>
```

`priority` is one of `high`, `medium`, `low`. A target with no entry defaults to
`medium` (fail-safe: an operator forgetting to classify a brand-new target does not
silently starve it of rig time, nor does it silently dominate the cycle). Within one
rig cycle, the runner should give `high` targets more turns than `medium`, and `medium`
more than `low` — the exact ratio (e.g. 4:2:1) is a `fuzz-harness` runner concern, not
specified here; this file only supplies the classification, matching the same
separation of concerns as `targets.d/*.conf` supplying duration without specifying
scheduling.

Initial classification (security-weighted, mirroring the rationale `targets.conf`'s own
per-target comments already give for duration — see `targets.d/*.conf`, not repeated
here): every target whose own comment cites a real finding (`FuzzParseResponse`,
`FuzzSSRFGuardDifferential`, `FuzzOIDCIDTokenSingleConstraintViolation`, etc.) or
attacker-controlled untrusted input on an unauthenticated route
(`FuzzWebAuthnCredentialResponse`, `FuzzCanarySecretLeakage`) is `high`; saturated
targets the `targets.conf` header already flagged as "+0/run" are `low`; everything else
defaults to `medium` via the no-entry fallback above, so `BUDGET.tsv` only needs to list
exceptions, not all 93 targets — a smaller, more honestly-maintainable file than a
mandatory full enumeration would be, at the cost of not being a byte-for-byte registry
the way `targets.d/*.conf` is (there is no drift guard here matching `targets.conf`'s
tree-vs-declared check, because there is no "true" value in the tree to check a priority
tier against — an operator's classification is inherently a judgment call, not a
derivable fact).

## `scripts/fuzzing/validate-budget.sh`

A short, fast (no fuzzing, no long runs) validation script:

- Every line in `BUDGET.tsv` names a file that actually exists in `targets.d/`
  (catches a stale entry after a target is renamed/removed).
- Every priority value is one of `high`/`medium`/`low` (catches a typo).
- No duplicate target names (catches a copy-paste mistake).

Exit non-zero on any violation, printing every offending line (not just the first) —
matching this repo's own "no silent caps" convention. Suitable for a CI step once
`fuzz-harness` is wired to read `targets.d/` (not wired into `ci.yml` in this PR, since
CI doesn't otherwise know or care about the rig's own scheduling file yet; add that step
in the same PR that lands the `fuzz-harness` handoff).

## Harvest guard

"Harvest" = pulling a completed rig run's findings (new coverage-improving corpus
entries, crashers) off pve01 and into their respective destinations (private
`fuzz-corpus` repo for crashers, per `scripts/fuzzing/README.md`'s existing
`REPORT_MODE=private` default; a human-reviewed subset back into this repo's own
`testdata/fuzz/` — see "Corpus sync" below). The guard exists because an unattended,
long-running rig accumulating corpus entries indefinitely is a disk-exhaustion risk on
a machine nobody is watching in real time — not a hypothetical: PHASE0's own CT 240 run
hit a real disk-full stop condition mid-run (`~/proj/prompts/reports/PHASE0-RERUN.md`),
on hardware dedicated to a SINGLE measurement job with none of a continuous rig's
target rotation compounding the growth rate.

Guard behavior (design, not yet implemented — a `fuzz-harness` runner concern once
STEP 2 starts):

1. **Cadence**: harvest runs on a fixed interval (e.g. every 6h), not continuously —
   batching avoids thrashing the corpus-sync step below on every single new interesting
   input.
2. **Disk-safety pre-check**: before starting a new fuzz run for the next scheduled
   target, check available disk headroom on the corpus volume; refuse to start (loud,
   not silent) if headroom is below a floor, rather than starting and hitting the same
   disk-full failure mode PHASE0 already hit once.
3. **Retention**: only the MINIMIZED form of each new interesting/crashing input is
   kept past the harvest cycle that found it — Go's fuzzing engine already minimizes on
   discovery, so this is enforcing what the engine already does, not adding new work.

## Corpus sync

Two distinct destinations, already established by this repo's existing convention
(`scripts/fuzzing/README.md`), reiterated here for the rig's specific cadence:

- **Crashers** → private `keyorixhq/fuzz-corpus` repo, `REPORT_MODE=private` by default
  (never a public issue/PR — an unfixed own-code vuln must not be disclosed before the
  fix). This is unconditional and automatic; no human review gates the crash itself
  reaching that private repo, only whether/when it becomes a public disclosure.
- **New coverage-improving, non-crashing corpus entries** → NOT auto-committed to this
  repo's own `testdata/fuzz/`. A human reviews and red-proofs before it lands here,
  matching this codebase's own standing rule (`scripts/fuzzing/README.md`'s
  "Rediscovery / regression" gate): a corpus entry earns a place in version control by
  demonstrating it reaches a real invariant worth guarding forever, not merely by
  having been found. Auto-syncing every interesting input the rig finds would grow
  `testdata/fuzz/` unboundedly with entries nobody has verified are testing anything
  meaningful — the inverse of the "#2047 lesson" this session's C4 item already
  verified is still respected elsewhere in this repo.

## Rollout

- **STEP 1 (this PR)**: `targets.d/BUDGET.tsv` + `validate-budget.sh` + this document.
  No pve01 access, no long-running fuzz invocation performed to produce it.
- **STEP 2 (blocked on PHASE0)**: build the rig on pve01, wire `fuzz-runner.sh` to this
  repo's `targets.d/` (pending the external HANDOFF) and `BUDGET.tsv`, run a bounded
  (~1h) smoke test — NOT started until FUZZ-RIG.md records "GO STEP 2".
