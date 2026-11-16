#!/usr/bin/env bash
# run-matrix.sh — HW1 thermal/disk load matrix driver for pve01 (RootedCON talk I).
#
# WHAT IT DOES
#   Runs a storage x concurrency matrix of a fixed, synthetic "agent-like"
#   workload while scripts/hw/sample.sh records thermals and disk I/O. Each cell
#   is: 20 min under load, then 10 min cooldown (still sampled — the cooldown is
#   part of the temperature baseline). One CSV + one .events sidecar per cell.
#
#   Synthetic workload (one "copy" = one simulated agent session):
#     in a FRESH clone of this repo under the cell's storage, repeatedly run
#       nice -n NICE  env GOMAXPROCS=2  go build ./internal/core/...
#       nice -n NICE  env GOMAXPROCS=2  go test -p 2 -count=1 ./internal/core/...
#     back-to-back until the 20 min load window ends. Each build+test pass's wall
#     time is logged to <cell>.workload.tsv so summarize.py can report it.
#
#   Matrix (default):
#     baseline cell  N=0            (idle, storage-independent, run once)
#     storage A (HDD)        N=1,2,4
#     storage B (tmpfs ramtmp) N=1,2,4
#     storage C (GOCACHE on tmpfs, repo clone on HDD) N=1,2,4
#   => 1 + 9 = 10 cells. At 30 min/cell that is 5.0 h, inside the overnight
#   window. See .scratch/HW1-plan.md for the exact order and timings.
#
#   Isolation comparison (opt-in, ISOLATION=1): the SAME N=2 workload under
#   "plain user" vs whatever container/VM/ramtmp variants are ALREADY set up on
#   pve01. This driver only runs the variants you point it at via env; it never
#   installs or creates containers/VMs. See the plan for how to wire each.
#
# SAFETY / ABORT RULES (enforced live, every GUARD_INTERVAL_S seconds):
#   - CPU package temp  > CPU_ABORT_C (default 90) sustained CPU_ABORT_HOLD_S
#     (default 120 s)                           -> abort current cell + matrix
#   - any monitored disk temp > HDD_ABORT_C (default 55)   -> abort
#   - SMART reallocated count on any disk INCREASES vs the pre-matrix reading
#                                                         -> abort
#   On abort: kill the workload copies, stop the sampler, write ABORTED to the
#   cell .events, and exit non-zero. Nothing is left running.
#
#   Independently, a soft thermal brake pauses (does not abort) new work while
#   CPU temp is above CPU_PAUSE_C (default 92) as the shared-host rules require.
#
# PRE-FLIGHT
#   Refuses to start if another wave4 session looks active: any file matching
#   $WAVE4_OUT/*.status (default /mnt/data/wave4/out) containing "running".
#   Override only with FORCE=1 (recorded in the run log).
#
# USAGE
#   scripts/hw/run-matrix.sh [RESULTS_DIR]
#     RESULTS_DIR default: .scratch/hw1-matrix-<epoch>
#
# This script starts/stops the sampler and the workload, reads temps to enforce
# aborts, and writes only under RESULTS_DIR and the per-cell clone roots it owns.
# It does not touch other directories under /mnt/data or any container.

set -u

# ----------------------------- configuration --------------------------------
REPO_ROOT="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SAMPLER="$REPO_ROOT/scripts/hw/sample.sh"

RESULTS_DIR="${1:-$REPO_ROOT/.scratch/hw1-matrix-$(date +%s)}"

LOAD_S="${LOAD_S:-1200}"        # 20 min under load
COOLDOWN_S="${COOLDOWN_S:-600}" # 10 min cooldown (sampled)
NICE="${NICE:-10}"
GOMAXPROCS_VAL="${GOMAXPROCS_VAL:-2}"
GOTEST_P="${GOTEST_P:-2}"
WORKLOAD_PKG="${WORKLOAD_PKG:-./internal/core/...}"

# Storage roots (override to match pve01's actual mounts).
HDD_ROOT="${HDD_ROOT:-/mnt/data/wave4/hw1-matrix}"
TMPFS_ROOT="${TMPFS_ROOT:-/mnt/ramtmp}"   # see 2026-11-13-pve01-ramtmp-tmpfs doc
[[ -d "$TMPFS_ROOT" ]] || TMPFS_ROOT="/dev/shm"

# Shared, pre-populated module cache (no per-cell download; sessions are offline).
GOMODCACHE_SHARED="${GOMODCACHE:-/mnt/data/wave4/gomod}"

# Abort / brake thresholds.
CPU_ABORT_C="${CPU_ABORT_C:-90}"
CPU_ABORT_HOLD_S="${CPU_ABORT_HOLD_S:-120}"
HDD_ABORT_C="${HDD_ABORT_C:-55}"
CPU_PAUSE_C="${CPU_PAUSE_C:-92}"
GUARD_INTERVAL_S="${GUARD_INTERVAL_S:-15}"

WAVE4_OUT="${WAVE4_OUT:-/mnt/data/wave4/out}"

# Concurrency levels and storages for the main matrix.
NS=(1 2 4)
STORAGES=(A B C)

mkdir -p "$RESULTS_DIR"
RUNLOG="$RESULTS_DIR/run.log"
log() { echo "[$(date -Is 2>/dev/null || date)] $*" | tee -a "$RUNLOG" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# Recursively terminate a PID and all of its descendants (go build/test included).
kill_tree() {
  local pid="$1" child
  for child in $(pgrep -P "$pid" 2>/dev/null); do kill_tree "$child"; done
  kill "$pid" 2>/dev/null
}

# Globals tracking the currently-running cell, cleaned up on any exit/interrupt
# so no sampler or workload is ever left behind.
CURRENT_SAMPLER=""
CURRENT_PIDS=()
cleanup() {
  local p
  for p in "${CURRENT_PIDS[@]:-}"; do [[ -n "$p" ]] && kill_tree "$p"; done
  [[ -n "$CURRENT_SAMPLER" ]] && kill "$CURRENT_SAMPLER" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ----------------------------- pre-flight -----------------------------------
preflight() {
  if ! have go; then log "FATAL: go not found in PATH"; exit 3; fi
  if [[ ! -x "$SAMPLER" ]]; then log "FATAL: sampler not executable: $SAMPLER"; exit 3; fi
  local active=0 f
  shopt -s nullglob
  for f in "$WAVE4_OUT"/*.status; do
    if grep -qi running "$f" 2>/dev/null; then
      log "another wave4 session appears active: $f"; active=1
    fi
  done
  shopt -u nullglob
  if [[ "$active" -eq 1 && "${FORCE:-0}" != "1" ]]; then
    log "ABORT pre-flight: a wave4 session is running (set FORCE=1 to override)."
    exit 4
  fi
  [[ "$active" -eq 1 ]] && log "WARNING: overriding active-session check (FORCE=1)."
  log "pre-flight OK. results=$RESULTS_DIR go=$(go version 2>/dev/null)"
}

# ------------------------- temperature helpers ------------------------------
# Reuse the sampler's package-input autodetect by sourcing nothing; inline a
# minimal reader so the guard does not depend on the sampler's internals.
PKG_INPUT=""
detect_pkg_input() {
  [[ -n "${HWMON_PKG:-}" ]] && { echo "$HWMON_PKG"; return; }
  local h nm lf label
  for h in /sys/class/hwmon/hwmon*; do
    [[ -r "$h/name" ]] || continue
    read -r nm <"$h/name" 2>/dev/null || continue
    [[ "$nm" == coretemp || "$nm" == k10temp || "$nm" == zenpower ]] || continue
    for lf in "$h"/temp*_label; do
      [[ -r "$lf" ]] || continue
      read -r label <"$lf" 2>/dev/null || continue
      if [[ "$label" == "Package id 0" || "$label" == Tctl || "$label" == Tdie ]]; then
        echo "${lf%_label}_input"; return
      fi
    done
    [[ -r "$h/temp1_input" ]] && { echo "$h/temp1_input"; return; }
  done
  echo ""
}
cpu_temp_c() {
  [[ -z "$PKG_INPUT" ]] && PKG_INPUT="$(detect_pkg_input)"
  [[ -n "$PKG_INPUT" && -r "$PKG_INPUT" ]] || { echo "NA"; return; }
  local v; read -r v <"$PKG_INPUT" 2>/dev/null || { echo "NA"; return; }
  [[ "$v" =~ ^-?[0-9]+$ ]] || { echo "NA"; return; }
  awk -v v="$v" 'BEGIN{printf "%d", v/1000}'
}
disk_temp_c() {  # arg: device name; uses smartctl if present
  local dev="$1"
  have smartctl || { echo "NA"; return; }
  smartctl -A "/dev/$dev" 2>/dev/null | awk '
    /Temperature_Celsius/ {print $10; f=1; exit}
    /^Temperature:/       {print $2; f=1; exit}
    END{if(!f) print "NA"}'
}
disk_realloc() { # arg: device; raw reallocated count or NA
  local dev="$1"
  have smartctl || { echo "NA"; return; }
  smartctl -A "/dev/$dev" 2>/dev/null | awk '
    /Reallocated_Sector_Ct/ {print $10; f=1; exit}
    END{if(!f) print "NA"}'
}

# ------------------------- storage wiring -----------------------------------
# Echoes "CLONE_PARENT|GOCACHE_DIR" for a storage letter + cell tag.
storage_dirs() {
  local st="$1" tag="$2"
  case "$st" in
    A) echo "$HDD_ROOT/$tag|$HDD_ROOT/$tag/gocache" ;;
    B) echo "$TMPFS_ROOT/$tag|$TMPFS_ROOT/$tag/gocache" ;;
    C) echo "$HDD_ROOT/$tag|$TMPFS_ROOT/$tag/gocache" ;;
    *) echo "$HDD_ROOT/$tag|$HDD_ROOT/$tag/gocache" ;;
  esac
}

# A single workload copy: clone, then loop build+test until the deadline.
# args: clone_parent gocache copy_id deadline_epoch workload_tsv
run_copy() {
  local parent="$1" gocache="$2" cid="$3" deadline="$4" wtsv="$5"
  local clone="$parent/clone-$cid"
  mkdir -p "$parent" "$gocache"
  # Local clone from this repo; --no-hardlinks so the copy truly lives on the
  # target storage (hardlinks would share inodes with the source filesystem).
  if ! git clone --quiet --local --no-hardlinks "$REPO_ROOT" "$clone" 2>>"$RUNLOG"; then
    log "copy $cid: clone failed"; return 1
  fi
  local iter=0
  while :; do
    local now; now="$(date +%s)"
    (( now >= deadline )) && break
    iter=$((iter+1))
    local t0 t1 rc
    t0="$(date +%s.%N)"
    ( cd "$clone" && \
      GOMAXPROCS="$GOMAXPROCS_VAL" GOCACHE="$gocache" GOMODCACHE="$GOMODCACHE_SHARED" \
      TMPDIR="$parent/tmp-$cid" \
      nice -n "$NICE" go build "$WORKLOAD_PKG" >>"$parent/copy-$cid.build.log" 2>&1 && \
      GOMAXPROCS="$GOMAXPROCS_VAL" GOCACHE="$gocache" GOMODCACHE="$GOMODCACHE_SHARED" \
      TMPDIR="$parent/tmp-$cid" \
      nice -n "$NICE" go test -p "$GOTEST_P" -count=1 "$WORKLOAD_PKG" >>"$parent/copy-$cid.test.log" 2>&1 )
    rc=$?
    t1="$(date +%s.%N)"
    mkdir -p "$parent/tmp-$cid"
    awk -v c="$cid" -v i="$iter" -v a="$t0" -v b="$t1" -v rc="$rc" \
      'BEGIN{printf "%s\t%s\t%.2f\t%s\n", c, i, b-a, rc}' >>"$wtsv"
  done
  return 0
}

# ------------------------- one matrix cell ----------------------------------
# args: cell_tag storage N
run_cell() {
  local tag="$1" st="$2" n="$3"
  local csv="$RESULTS_DIR/$tag.csv"
  local events="$RESULTS_DIR/$tag.events"
  local wtsv="$RESULTS_DIR/$tag.workload.tsv"
  : >"$wtsv"
  printf 'copy\titer\twall_s\trc\n' >"$wtsv"

  log "CELL $tag: storage=$st N=$n  load=${LOAD_S}s cooldown=${COOLDOWN_S}s"

  # Start the sampler for this cell (writes continuously through cooldown).
  DISK_TARGET="$HDD_ROOT" "$SAMPLER" "$csv" &
  local sampler_pid=$!
  CURRENT_SAMPLER="$sampler_pid"

  local run_start; run_start="$(date +%s)"
  echo "RUN_START=$run_start" >"$events"
  echo "STORAGE=$st" >>"$events"
  echo "N=$n" >>"$events"

  # Launch N workload copies.
  local parent gocache; IFS='|' read -r parent gocache < <(storage_dirs "$st" "$tag")
  echo "CLONE_PARENT=$parent" >>"$events"
  echo "GOCACHE=$gocache" >>"$events"
  local load_start; load_start="$(date +%s)"
  echo "LOAD_START=$load_start" >>"$events"
  local deadline=$((load_start + LOAD_S))
  local pids=()
  local i
  for ((i=1; i<=n; i++)); do
    run_copy "$parent" "$gocache" "$i" "$deadline" "$wtsv" &
    pids+=($!)
  done
  CURRENT_PIDS=("${pids[@]}")

  # Guard loop until the load deadline, then into cooldown.
  local over_since=0 aborted=0 phase="load" cool_deadline=0
  while :; do
    local now; now="$(date +%s)"
    if [[ "$phase" == "load" && "$now" -ge "$deadline" ]]; then
      # Load window done: stop any still-running copies, begin cooldown.
      local p; for p in "${pids[@]}"; do kill_tree "$p"; done
      echo "LOAD_END=$(date +%s)" >>"$events"
      log "CELL $tag: load window complete, entering cooldown"
      phase="cooldown"; cool_deadline=$((now + COOLDOWN_S))
    fi
    if [[ "$phase" == "cooldown" && "$now" -ge "$cool_deadline" ]]; then
      break
    fi

    # --- abort checks ---
    local ct; ct="$(cpu_temp_c)"
    if [[ "$ct" != "NA" ]]; then
      if (( ct > CPU_ABORT_C )); then
        [[ "$over_since" -eq 0 ]] && over_since="$now"
        if (( now - over_since >= CPU_ABORT_HOLD_S )); then
          log "ABORT: CPU ${ct}C > ${CPU_ABORT_C}C for >= ${CPU_ABORT_HOLD_S}s"; aborted=1
        fi
      else
        over_since=0
      fi
      if (( ct > CPU_PAUSE_C )); then
        log "thermal brake: CPU ${ct}C > ${CPU_PAUSE_C}C — pausing new work 60s"
        # Pausing here throttles the guard; copies keep their own nice priority.
        sleep 60; continue
      fi
    fi
    local dev
    for dev in $(tr ' ' '\n' <<<"${DISKS:-$(cat "$RESULTS_DIR/.disks" 2>/dev/null)}"); do
      [[ -z "$dev" || "$dev" == "NA" ]] && continue
      local dt rc_realloc
      dt="$(disk_temp_c "$dev")"
      if [[ "$dt" != "NA" ]] && (( dt > HDD_ABORT_C )); then
        log "ABORT: disk $dev ${dt}C > ${HDD_ABORT_C}C"; aborted=1
      fi
      rc_realloc="$(disk_realloc "$dev")"
      local base; base="$(cat "$RESULTS_DIR/.realloc.$dev" 2>/dev/null || echo NA)"
      if [[ "$rc_realloc" != "NA" && "$base" != "NA" ]] && (( rc_realloc > base )); then
        log "ABORT: disk $dev reallocated $base -> $rc_realloc (INCREASED)"; aborted=1
      fi
    done

    if [[ "$aborted" -eq 1 ]]; then
      local p; for p in "${pids[@]}"; do kill_tree "$p"; done
      kill "$sampler_pid" 2>/dev/null
      CURRENT_SAMPLER=""; CURRENT_PIDS=()
      echo "ABORTED=$(date +%s)" >>"$events"
      log "CELL $tag ABORTED — stopping matrix"
      return 42
    fi
    sleep "$GUARD_INTERVAL_S"
  done

  # Cooldown complete: stop the sampler, clean up clones.
  echo "CELL_END=$(date +%s)" >>"$events"
  kill "$sampler_pid" 2>/dev/null
  wait "$sampler_pid" 2>/dev/null
  CURRENT_SAMPLER=""; CURRENT_PIDS=()
  # Remove this cell's clones + GOCACHE to reclaim storage (esp. tmpfs). For
  # storage C the GOCACHE lives on tmpfs outside $parent, so remove it too.
  rm -rf "$parent" 2>/dev/null || true
  [[ -n "$gocache" && "$gocache" != "$parent"/* ]] && rm -rf "$gocache" 2>/dev/null || true
  log "CELL $tag: done (clones removed)"
  return 0
}

# ------------------------------- main ---------------------------------------
main() {
  preflight

  # Record baseline SMART reallocated counts + the disk list for the guard.
  # Create the HDD root first so df resolves its real backing device (not a
  # fallback) — we own this directory.
  mkdir -p "$HDD_ROOT"
  # Derive the monitored disk the same way the sampler does (df -> parent disk).
  local primary base; base="$(df -P "$HDD_ROOT" 2>/dev/null | awk 'NR==2{print $1}' | xargs -r basename)"
  primary=""
  if [[ -n "$base" && -e "/sys/class/block/$base" ]]; then
    local parent; parent="$(basename -- "$(dirname -- "$(readlink -f "/sys/class/block/$base")")")"
    if [[ "$parent" != "block" && -e "/sys/class/block/$parent" ]]; then primary="$parent"; else primary="$base"; fi
  fi
  [[ -z "$primary" ]] && primary="$(awk '$3 ~ /^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+)$/ {print $3; exit}' /proc/diskstats 2>/dev/null)"
  echo "${DISKS:-$primary}" >"$RESULTS_DIR/.disks"
  local d
  for d in $(tr ' ' '\n' <"$RESULTS_DIR/.disks"); do
    [[ -z "$d" || "$d" == "NA" ]] && continue
    disk_realloc "$d" >"$RESULTS_DIR/.realloc.$d"
    log "baseline SMART reallocated($d)=$(cat "$RESULTS_DIR/.realloc.$d")"
  done

  # Pre-populate the shared module cache once (quiet; offline-safe if already warm).
  log "warming module cache in $GOMODCACHE_SHARED"
  ( cd "$REPO_ROOT" && GOMODCACHE="$GOMODCACHE_SHARED" GOFLAGS=-mod=mod go mod download 2>>"$RUNLOG" ) || \
    log "note: go mod download returned non-zero (likely offline + already warm)"

  # Cell 0: idle baseline (storage-independent).
  if ! run_cell "cell00-idle-N0" X 0; then
    log "baseline cell aborted — stopping"; exit 42
  fi

  # Main matrix.
  local st n tag
  for st in "${STORAGES[@]}"; do
    for n in "${NS[@]}"; do
      tag="cell-${st}-N${n}"
      if ! run_cell "$tag" "$st" "$n"; then
        log "matrix stopped at $tag"; exit 42
      fi
    done
  done

  # Optional isolation comparison (opt-in; only what is already set up).
  if [[ "${ISOLATION:-0}" == "1" ]]; then
    log "ISOLATION phase: run the N=2 workload under each configured variant."
    log "This driver runs the 'plain' variant here; container/VM/ramtmp variants"
    log "must be launched by the host operator per .scratch/HW1-plan.md (nothing"
    log "is installed or created by this script)."
    run_cell "iso-plain-N2" A 2 || { log "isolation(plain) aborted"; exit 42; }
    if [[ -n "${ISO_RAMTMP:-}" ]]; then
      run_cell "iso-ramtmp-N2" B 2 || { log "isolation(ramtmp) aborted"; exit 42; }
    fi
  fi

  log "MATRIX COMPLETE. CSVs + .events in $RESULTS_DIR"
  log "next: python3 scripts/hw/summarize.py $RESULTS_DIR"
}

main "$@"
