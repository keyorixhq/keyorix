# DD3 — Replay recording-gap silent false-OK (Packages, and every collector)

Task DD3 on branch `fuzz/dd3-replay-gap-verdict` (based on `fuzz/dd2-capture-replay`).
Written in English and updated as results arrive, so a report exists even if the run
is cut short.

## Interpretation / assumptions (stated, not asked)

Nobody answers questions in this unattended run; the most reasonable reading was taken:

- **The bug** is the false-OK the DD2 fuzzer (`FuzzCaptureReplayMutationRobustness`)
  found: replaying a bundle with the `apt-get --version` probe dropped makes the
  `Packages` check — `WARN` on the undamaged baseline — read `OK`.
- **The fix layer** is the analysis loop (`ApplyThresholds`), generic across all
  collectors, not a `Packages` special case.
- **Do not weaken the oracle.** The fuzz anti-false-OK invariant stays as-is; the fix
  makes the check stop reading `OK`, which is what the invariant already demands.

## The defect

`FuzzCaptureReplayMutationRobustness` input `uint16(0) byte(7) string("")` drops the
index entry and blob for `commands/blobs/0000.out` (`apt-get --version`) from
`fixtures/replay-fidelity/debian13-vmware-unsynced.tar.gz`, then replays.

Root cause (verified):

1. Baseline `Packages` = **WARN** "no security repository configured"
   (`PackagesInfo.Status == "no-security-repo"`).
2. Dropping the `apt-get --version` output makes the replayed `PackagesCollector`
   detect the package manager as **`"unknown"`** and sets `Result.NotRecorded = true`
   (`internal/runner/runner.go:55`, via `source.ErrNotRecorded`).
3. With `PackageManager == "unknown"`, every branch of `checkPackages`
   (`internal/analysis/heuristics_packages.go`) returns nothing:
   - `checkPackageDBHealth` is deliberately gated off for `"unknown"` (so a host with
     genuinely no package manager gets no spurious disclosure);
   - `checkPackageUpdates` sees `Status == ""`, `SecurityUpdates == 0` → `nil`;
   - integrity/extras → empty.
4. `ApplyThresholds` calls `markNotRecorded(got)`, but that only **relabels existing
   Unverified insights**; on an empty slice it is a no-op.
5. `render.BuildJSONOutput` (`internal/render/json.go:184-214`) then emits the
   `Packages` result with its default `Status: "OK"` — no insight owns it.
   → **silent false-OK**: a recording gap read as a green light.

This is **not** specific to Packages. The same shape — `if !X.Detected { return nil }`
or an `"unknown"`/empty-key early return — exists in ~36 heuristics files
(`checkElasticsearch`, `checkRedis`, `checkEnvoy`, `checkGrafana`, …). On replay, if
the input that drives detection is dropped, `Detected` flips to `false`, the check
returns `nil`, and the gap is silent. The existing `checks_never_silent` guard only
covers the *measured-but-unreadable* case (e.g. `{Detected: true, HealthRead:
false}`), not the *detection-input-dropped* case — which is only reachable under
replay and is what DD3 fixes.

**Classification: DEFECT (false-OK / fail-open on replay).** A replay-surface
correctness bug in dashdiag's own analysis loop. The DD2 fuzzer found it at first
contact; the production fix is in-scope for this task.

## The fix

`internal/analysis/heuristics.go`, `ApplyThresholds` loop: when
`Result.NotRecorded` is set **and** the collector produced no insight (after
`markNotRecorded`), synthesize one Unverified `INFO` with reason `not_recorded`
naming the collector. It is the empty-slice twin of `markNotRecorded`, applied once
in the loop for every collector.

- **Replay-only.** `NotRecorded` is never set on a live run (`runner.GapCount ==
  nil`), so live `dsd health` output is unchanged.
- **No spurious disclosure for a host with genuinely no package manager.** Live:
  `NotRecorded == false`. Replay of an honestly-recorded "no package manager" bundle:
  the collector read what the bundle recorded, so `NotRecorded == false` → no INFO.
- **The check stops reading `OK`** (becomes `INFO`, `unverified_reason:
  not_recorded`) — the oracle is satisfied, not weakened.

## Red/green proof

- **RED:** `FuzzCaptureReplayMutationRobustness/dd3_drop_pkgmgr_probe` fails before the
  fix (`FALSE-OK: check "Packages" … replayed OK`).
- **GREEN:** same seed passes after the fix.
- **Unit guard:** `TestApplyThresholds_ReplayGapSilentCollectorSurfacesInfo`
  (`internal/analysis/unverified_reason_test.go`) — a table over the loop's behaviour:
  silent replayed collector → synthetic `not_recorded` INFO; live silent collector →
  nothing (live unchanged); replayed collector with an existing Unverified insight →
  relabel only, no duplicate; replayed collector with a real WARN → finding survives,
  no spurious INFO. Fails without the fix (first row), passes with it.
- **Regression seed committed** at
  `cmd/testdata/fuzz/FuzzCaptureReplayMutationRobustness/dd3_drop_pkgmgr_probe`.

## What the oracles do NOT verify

- `FuzzCaptureReplayMutationRobustness` is single-direction (non-OK must not become
  OK) over one fixture host at one instant: it does not prove the baseline verdicts
  are themselves correct; it damages one input at a time; it cannot see a false-OK on
  a check the baseline already reports `OK`.
- The unit test exercises the loop through the `Packages` collector as the concrete
  silent case; it asserts the loop's *generic* behaviour but does not enumerate every
  collector's early-return paths (the fix keys on `Result.NotRecorded` + empty insight
  slice, not on any check identity, so it is collector-agnostic by construction).
- Neither oracle asserts message wording is operator-perfect — only that an Unverified
  `not_recorded` INFO is present and the check is no longer `OK`.
- **Residual (by design):** the fix triggers only when a `NotRecorded` collector
  produces *zero* insights. A collector that touched a gap but still emitted at least
  one insight is assumed to have said enough; in the rare case where that lone insight
  is an explicit `OK`-level one (most checks emit nothing when healthy, so this is
  uncommon), the gap would not add an INFO. No current collector was observed to hit
  this; widening to "no non-OK insight" was left out to avoid demoting genuine partial
  findings. Flagged here rather than silently scoped away.

## Test results

- `internal/analysis` full suite: PASS (incl. `TestAllChecksRegistered` governance).
- `cmd` full suite: (recorded in the run log).
- Fuzz re-run (`-fuzztime 540s` chunks): (recorded in the run log).
