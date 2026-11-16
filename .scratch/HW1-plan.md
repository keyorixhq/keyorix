# HW1 — pve01 thermal & disk measurement plan (RootedCON talk I)

**Interpretation note (no one answers questions, so this is the reading I ran
with):** my session cannot read `/sys` hwmon and cannot write
`/mnt/data/wave4/out`, so this deliverable is the *measurement harness*
(`scripts/hw/{sample.sh,run-matrix.sh,summarize.py}`) plus this plan and the
report template. **Andrei (or the host-side runner) executes the matrix on pve01
as root.** Every figure the talk quotes must come out of the CSVs these scripts
write — nothing here is estimated.

Branch note: the task text says "commit on branch `hw1-measurements`", but the
runtime rules say "stay on its branch" and the worktree is on
`fuzz/hw1-thermal-measure`. The runtime rules win, so the work is committed
there, unpushed. Rename/cherry-pick to `hw1-measurements` host-side if desired.

---

## What each script does (one line each)

- `scripts/hw/sample.sh <out.csv>` — every ~10 s appends one CSV row per
  monitored disk: CPU package temp, per-core max temp, load1, CPU %busy, fan
  rpm, and per-disk `iostat -x` (r/s, w/s, MB/s r/w, %util, await), plus
  `smartctl` disk temp + Wear/Reallocated/Power-On refreshed every 10 min. Any
  absent tool/source is written as literal `NA` and flagged in the CSV header.
- `scripts/hw/run-matrix.sh [results_dir]` — drives the storage×concurrency
  matrix, 20 min load + 10 min cooldown per cell, fresh clone per workload copy,
  live abort guard. One `<cell>.csv` + `<cell>.events` + `<cell>.workload.tsv`
  per cell.
- `scripts/hw/summarize.py <results_dir>` — reduces the CSVs to per-cell
  median/p95/peak temp, seconds above 80 C, MB written, %util, await, and
  workload wall time. Writes `SUMMARY.md` + `SUMMARY.csv`.

## The synthetic agent workload (one "copy" = one simulated agent session)

In a fresh `git clone --local --no-hardlinks` of this repo placed on the cell's
storage, loop until the 20 min window ends:

```
GOMAXPROCS=2 nice -n 10 go build ./internal/core/...
GOMAXPROCS=2 nice -n 10 go test -p 2 -count=1 ./internal/core/...
```

`-count=1` defeats the test cache so each pass does real work; `GOCACHE` is per
cell (placed per the storage under test) so the build cache lives on the storage
being measured; `GOMODCACHE` is shared and pre-warmed once (modules are not the
variable under test, and sessions are offline).

## The matrix (run order)

| # | cell tag          | storage                              | N | load | cooldown |
|---|-------------------|--------------------------------------|---|------|----------|
| 0 | cell00-idle-N0    | — (idle baseline, storage-indep.)    | 0 | 20m  | 10m      |
| 1 | cell-A-N1         | A: /mnt/data (HDD)                   | 1 | 20m  | 10m      |
| 2 | cell-A-N2         | A: HDD                               | 2 | 20m  | 10m      |
| 3 | cell-A-N4         | A: HDD                               | 4 | 20m  | 10m      |
| 4 | cell-B-N1         | B: tmpfs ramtmp (repo+cache in RAM)  | 1 | 20m  | 10m      |
| 5 | cell-B-N2         | B: tmpfs ramtmp                      | 2 | 20m  | 10m      |
| 6 | cell-B-N4         | B: tmpfs ramtmp                      | 4 | 20m  | 10m      |
| 7 | cell-C-N1         | C: GOCACHE on tmpfs, repo on HDD     | 1 | 20m  | 10m      |
| 8 | cell-C-N2         | C: GOCACHE on tmpfs, repo on HDD     | 2 | 20m  | 10m      |
| 9 | cell-C-N4         | C: GOCACHE on tmpfs, repo on HDD     | 4 | 20m  | 10m      |

The cooldown is sampled too and counts toward the temperature baseline
(`summarize.py` reports `cool_peak` separately).

**Expected total runtime:** 10 cells × 30 min = **5.0 h**, plus ~5 min module
cache warm + baseline SMART reads ≈ **~5.2 h**. Fits one overnight window
(budget ≤ 10 h) with margin. N=0 is run once (idle is storage-independent),
which is the cut that keeps it from becoming 12 cells / 6 h.

### Optional isolation comparison (opt-in: `ISOLATION=1`)

Same N=2 workload under: plain user (run by this driver), and
container/VM/ramtmp variants **only if already set up on pve01** — this driver
installs and creates nothing. Adds ~30 min per variant. To include the ramtmp
variant set `ISO_RAMTMP=1`. Container/VM variants: launch the same
`go build/test` loop by hand inside the pre-existing container/VM against a clone
on its storage, run a `sample.sh` on the host in parallel, and label the CSV
`iso-container-N2` / `iso-vm-N2` so `summarize.py` picks it up. If no
container/VM is pre-provisioned, report that row as "not available on pve01" —
do not install one.

## Abort rules (enforced live by run-matrix.sh, re-checked every 15 s)

- **CPU package temp > 90 C sustained for ≥ 120 s** → kill workload + sampler,
  mark cell `ABORTED`, stop the whole matrix.
- **Any monitored disk temp > 55 C** → abort.
- **SMART reallocated-sector count increases** vs the reading taken before the
  matrix started → abort (protects the HDD; a rising reallocated count is real
  media damage).
- Soft brake (pause, not abort): while CPU > 92 C the guard pauses new work 60 s,
  per the shared-host rule.

On any abort nothing is left running (process-tree kill + EXIT/INT/TERM trap).

## What Andrei must run (host-side, as root, no other wave4 session active)

```sh
# 0. Confirm no other wave4 session is live (the driver also checks out/*.status).
# 1. Point the driver at the real mounts if they differ from the defaults:
#    HDD_ROOT=/mnt/data/wave4/hw1-matrix  TMPFS_ROOT=/mnt/ramtmp (per the
#    2026-11-13-pve01-ramtmp-tmpfs doc)  DISKS="sda"   (optional overrides)
sudo env HDD_ROOT=/mnt/data/wave4/hw1-matrix TMPFS_ROOT=/mnt/ramtmp \
     scripts/hw/run-matrix.sh /mnt/data/wave4/hw1/.scratch/hw1-matrix-run1

# 2. Summarize:
python3 scripts/hw/summarize.py /mnt/data/wave4/hw1/.scratch/hw1-matrix-run1

# 3. Copy SUMMARY.md's figures into the report (see .scratch/hw1-REPORT.md).
```

Defaults if env is unset: `HDD_ROOT=/mnt/data/wave4/hw1-matrix`,
`TMPFS_ROOT=/mnt/ramtmp` (falls back to `/dev/shm`),
`GOMODCACHE=/mnt/data/wave4/gomod`, nice 10, GOMAXPROCS 2, `go test -p 2`.

## Known limits of this harness (stated honestly, per the runtime rules)

- **Storage B (tmpfs) produces ~no HDD disk I/O** — writes land in RAM, so
  `%util`/MB-written for the HDD will read near-zero by design. That *is* the
  finding (RAM-backed builds spare the disk), not a measurement gap; the report
  says so.
- `cpu_busy_pct` is whole-host from `/proc/stat` deltas over the iostat window,
  not per-workload.
- `await`/`%util` come from `iostat` interval averages; sub-10 s bursts are
  smoothed out.
- SMART wear/temp semantics vary by drive vendor; the sampler records the raw/
  normalized attribute and the report must not over-interpret a single number.
- The guard reads the same package-temp input the sampler autodetects; if that
  input is absent (`pkg_temp=NA` in the header) the CPU abort cannot fire —
  in that case rely on nice/GOMAXPROCS/-parallel 2 and watch disk temp, and say
  so in the report.
