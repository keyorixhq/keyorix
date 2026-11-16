# HW1 — pve01 thermal & disk load under parallel agent sessions

**Talk:** RootedCON talk I — "an AI software factory without cooking the
hardware." **Goal:** measured numbers, not estimates, for CPU temperature, disk
I/O and SMART wear while N concurrent synthetic agent sessions build+test the
Keyorix core under different storage backings.

**Report location.** This report is committed on the branch at
`.scratch/hw1-REPORT.md`. The intended path `/mnt/data/wave4/out/hw1-REPORT.md`
is not writable from this (sandboxed) session — the task constraints state the
session cannot write `/mnt/data/wave4/out` and must not work around it — so per
the runtime "REPORT PATH" fallback the report stays here. Copy it host-side if
the `out/` path is required.

**Status: harness delivered, matrix NOT yet run.** This session writes the
measurement scripts, the run plan and this template; it cannot read `/sys` hwmon
or run the load itself (sandbox + shared-host rules). Andrei / the host-side
runner executes `scripts/hw/run-matrix.sh` on pve01 as root and fills the result
tables below from `SUMMARY.md`. **Every figure the talk quotes must come from the
CSVs these scripts produce — this document contains no estimated numbers.**

---

## 1. Interpretation decisions (no one answers questions mid-run)

1. The session cannot read hwmon or write `out/`, so the deliverable is the
   *harness* + plan + report template; the host runs the matrix. (Explicit in
   the task.)
2. Branch: committed on `fuzz/hw1-thermal-measure` (the worktree's branch) not
   `hw1-measurements`, because the runtime rules "stay on its branch" override
   the task's branch name. Rename host-side if needed.
3. Matrix trimmed to **10 cells / ~5.2 h** (idle baseline run once, not per
   storage) to fit the overnight window with margin.
4. CSV is **long format** — one row per (timestamp, disk) — so the header is
   stable when more than one disk is monitored; with a single disk it is exactly
   one row per 10 s as the brief asks.

## 2. What was delivered (committed on this branch)

| File | Purpose |
|------|---------|
| `scripts/hw/sample.sh` | 10 s thermal/disk/SMART sampler → CSV (NA for any missing tool) |
| `scripts/hw/run-matrix.sh` | storage×N matrix driver, 20m load + 10m cooldown, live abort guard |
| `scripts/hw/summarize.py` | per-cell median/p95/peak temp, s>80C, MB written, %util, await, wall time |
| `.scratch/HW1-plan.md` | exact run order, timings, abort rules, what Andrei runs |
| `.scratch/hw1-REPORT.md` | this report |

Verification status of the scripts: syntax/execution could **not** be run in
this session (the sandbox gates `bash`/`python3` execution, and hwmon/iostat are
unreadable here). They were verified by review only. **First action host-side
must be a smoke test** before the full run (section 6).

## 3. The measurement (method)

- **Workload per copy (= one simulated agent session):** fresh
  `git clone --local --no-hardlinks` on the cell's storage, then loop
  `GOMAXPROCS=2 nice -n 10 go build ./internal/core/...` +
  `go test -p 2 -count=1 ./internal/core/...` until the 20 min window ends.
- **Matrix:** idle N=0 (once) + storage {A=HDD, B=tmpfs ramtmp, C=GOCACHE on
  tmpfs/repo on HDD} × N={1,2,4}. 20 min load + 10 min cooldown each.
- **Sampling:** every 10 s; `iostat -x` paces the loop and gives true interval
  averages; SMART (disk temp, wear, reallocated, power-on) every 10 min.

## 4. Results — fill from `SUMMARY.md` after the run

> Paste the `summarize.py` table here. Template:

| cell | stor | N | temp_med | temp_p95 | temp_peak | s>80C | dtemp_peak | MB_writ | util_med | util_peak | await_med | wall_med | wall_p95 | passes | cool_peak |
|------|------|---|----------|----------|-----------|-------|-----------|---------|----------|-----------|-----------|----------|----------|--------|-----------|
| cell00-idle-N0 | — | 0 | _ | _ | _ | _ | _ | _ | _ | _ | _ | — | — | — | _ |
| cell-A-N1 | A | 1 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-A-N2 | A | 2 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-A-N4 | A | 4 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-B-N1 | B | 1 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-B-N2 | B | 2 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-B-N4 | B | 4 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-C-N1 | C | 1 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-C-N2 | C | 2 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |
| cell-C-N4 | C | 4 | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ | _ |

Headline numbers to pull out for the talk (once filled):
- Idle vs N=4 peak package temp (Δ°C) and whether any cell crossed 80 C / 90 C.
- HDD (storage A) MB written & peak disk temp vs tmpfs (storage B, ≈0 disk I/O).
- Workload wall time A vs B vs C at the same N (the "RAM makes the factory
  faster AND cooler" claim — only if the CSV shows it).
- Cooldown peak vs load peak (how hot it stays after the burst).

## 5. What each oracle does NOT verify (required honesty section)

- **`sample.sh` CPU %busy** is whole-host (`/proc/stat` deltas), not
  per-workload; it cannot attribute heat to a specific agent copy.
- **`%util` / `await`** are `iostat` 10 s interval averages — sub-10 s I/O bursts
  are smoothed away; `%util` on a multi-queue device is not a true saturation
  measure.
- **Storage B (tmpfs)** writes to RAM, so HDD `%util`/MB-written read ≈ 0 by
  construction. That is the *finding* (RAM builds spare the disk and its wear),
  not a gap — but it means "disk load under tmpfs" is not measurable because
  there is none.
- **SMART wear/temp** semantics differ per drive vendor; a single `Wear` or
  `Reallocated` number is recorded raw and must not be over-read. Reallocated
  *increasing during the run* is the only SMART signal treated as actionable
  (it aborts).
- **Temperature abort** can only fire if the package-temp hwmon input is present
  (`pkg_temp` ≠ NA in the CSV header). If it is NA, the CPU-temp abort is
  inert and safety rests on nice/GOMAXPROCS/`-parallel 2` + the disk-temp abort;
  the run log and this section must say which case held.
- **The matrix does not isolate** CPU frequency scaling, ambient temperature, or
  other host tenants. The brief requires no other wave4 session during the run
  (the driver pre-flights `out/*.status`); ambient drift across a 5 h window is
  uncontrolled and should be noted if cell-to-cell baselines move.
- **`summarize.py`** computes statistics only; it does not test significance or
  model transient vs steady state. "Peak" is a single sample and can be noise.

## 6. Host-side run procedure (also in HW1-plan.md)

1. Confirm no other wave4 session is active.
2. **Smoke test first** (one short sample + a 1-copy micro cell), e.g.
   `SAMPLE_ONCE=1 scripts/hw/sample.sh /tmp/probe.csv` and inspect the header's
   `tools:` line to see which of iostat/smartctl/sensors are present and whether
   `pkg_temp_input` was found. If `go` is missing or hwmon is NA, note it.
3. Full run:
   `sudo env HDD_ROOT=/mnt/data/wave4/hw1-matrix TMPFS_ROOT=/mnt/ramtmp scripts/hw/run-matrix.sh <results_dir>`
4. `python3 scripts/hw/summarize.py <results_dir>` → paste `SUMMARY.md` into §4.
5. Record in §5 which oracles were live (hwmon present? iostat/smartctl present?)
   and whether any cell aborted (check each `<cell>.events` for `ABORTED`).

## 7. Findings (classified) — fill after the run

None yet — no data collected in this session. Classify any finding honestly
(EXPECTED-DIFFERENCE / DEFECT / ARTIFACT / HARDENING); replay 3× before any
claim. The expected EXPECTED-DIFFERENCE results (tmpfs ≈ 0 disk wear; higher N →
higher temp) must still be shown from the CSV, not asserted.

## 8. Proposed follow-ups (issue-ready, no production code touched here)

- If the matrix shows sustained >80 C at N=4 on HDD storage, propose capping
  concurrent agent sessions or pinning `GOMAXPROCS`/`-p` lower as the default on
  pve01 — backed by the `s>80C` column, not by feel.
- If tmpfs (storage B) both runs faster *and* keeps the CPU cooler at equal N,
  propose it as the default agent scratch storage, with the MB-written=0 column
  as the disk-wear argument.
