#!/usr/bin/env bash
# sample.sh — HW1 thermal/disk sampler for pve01 (RootedCON talk I).
#
# WHAT IT DOES
#   Every ~10 s it appends one CSV line PER MONITORED DISK to the file given as
#   the first argument. CPU/thermal fields are identical across the disk rows
#   that share a timestamp (long format — one row per (timestamp, disk)). With a
#   single monitored disk this is exactly one line per 10 s, as the HW1 brief asks;
#   the disk column is always present so the header never changes when more disks
#   are monitored.
#
#   The 10 s cadence is driven by `iostat -x -d -k 10 2`: iostat prints a
#   since-boot report immediately, waits 10 s, then prints the interval report we
#   actually parse. That single blocking call both paces the loop and gives a
#   true 10 s interval average for r/s, w/s, kB/s, %util and await.
#
#   SMART / disk-temperature fields (disk_temp_c, smart_wear,
#   smart_reallocated, smart_power_on_h) come from `smartctl -A`. They are
#   refreshed at most every SMART_INTERVAL_S seconds (default 600 = 10 min) and
#   the last-known value is repeated on every intervening line, so every CSV line
#   is self-contained.
#
#   Any metric whose tool or source is missing is written as the literal string
#   NA (never left blank, never faked). Which tools were found is recorded in the
#   header comment block of the CSV at creation time.
#
# USAGE
#   scripts/hw/sample.sh <output.csv>
#
# ENV (all optional)
#   DISKS            space-separated block device names to monitor (e.g. "sda sdb").
#                    Default: the device backing DISK_TARGET, else autodetect the
#                    first spinning/SSD disk from /proc/diskstats.
#   DISK_TARGET      path whose backing block device is monitored when DISKS unset
#                    (default: the directory of the CSV, falling back to /mnt/data).
#   SMART_INTERVAL_S SMART/disk-temp refresh period in seconds (default 600).
#   HWMON_PKG        explicit path to the package-temp input file
#                    (e.g. /sys/class/hwmon/hwmon2/temp1_input). Default: autodetect
#                    the coretemp "Package id 0" input.
#   SAMPLE_ONCE=1    take a single sample and exit (used by tests / smoke checks).
#
# Only standard tools are used: bash, awk, iostat (sysstat), smartctl
# (smartmontools), plus /proc and /sys. `sensors` is used if present but is not
# required — temps fall back to /sys/class/hwmon.
#
# This script only READS the machine and APPENDS to one file. It never changes
# system state. Intended to be run on pve01 as root by the host-side runner.

set -u

OUT="${1:-}"
if [[ -z "$OUT" ]]; then
  echo "usage: $0 <output.csv>" >&2
  exit 2
fi

SMART_INTERVAL_S="${SMART_INTERVAL_S:-600}"
DISK_TARGET="${DISK_TARGET:-$(dirname -- "$OUT")}"

have() { command -v "$1" >/dev/null 2>&1; }

HAVE_IOSTAT=0; have iostat && HAVE_IOSTAT=1
HAVE_SMARTCTL=0; have smartctl && HAVE_SMARTCTL=1
HAVE_SENSORS=0; have sensors && HAVE_SENSORS=1

# ---------------------------------------------------------------------------
# Disk selection
# ---------------------------------------------------------------------------
dev_for_path() {
  # Print the kernel block device name (e.g. sda) backing a path, or nothing.
  local p="$1" src
  src="$(df -P "$p" 2>/dev/null | awk 'NR==2{print $1}')"
  [[ -z "$src" ]] && return 0
  local base; base="$(basename -- "$src")"
  # Map a partition / dm name to its parent disk via /sys/class/block.
  if [[ -e "/sys/class/block/$base" ]]; then
    local real; real="$(readlink -f "/sys/class/block/$base" 2>/dev/null)"
    # Walk up until we hit an entry directly under /sys/.../block/<disk>.
    local parent; parent="$(basename -- "$(dirname -- "$real")")"
    if [[ "$parent" != "block" && -e "/sys/class/block/$parent" ]]; then
      echo "$parent"; return 0
    fi
    echo "$base"; return 0
  fi
  echo "$base"
}

if [[ -n "${DISKS:-}" ]]; then
  read -r -a DISK_LIST <<<"$DISKS"
else
  d="$(dev_for_path "$DISK_TARGET")"
  if [[ -z "$d" ]]; then
    d="$(awk '$3 ~ /^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+)$/ {print $3; exit}' /proc/diskstats 2>/dev/null)"
  fi
  [[ -z "$d" ]] && d="NA"
  DISK_LIST=("$d")
fi

# ---------------------------------------------------------------------------
# Package-temp source autodetect (coretemp "Package id 0")
# ---------------------------------------------------------------------------
detect_pkg_input() {
  [[ -n "${HWMON_PKG:-}" ]] && { echo "$HWMON_PKG"; return 0; }
  local h label
  for h in /sys/class/hwmon/hwmon*; do
    [[ -r "$h/name" ]] || continue
    read -r nm <"$h/name" 2>/dev/null || continue
    [[ "$nm" == "coretemp" || "$nm" == "k10temp" || "$nm" == "zenpower" ]] || continue
    for lf in "$h"/temp*_label; do
      [[ -r "$lf" ]] || continue
      read -r label <"$lf" 2>/dev/null || continue
      if [[ "$label" == "Package id 0" || "$label" == "Tctl" || "$label" == "Tdie" ]]; then
        echo "${lf%_label}_input"; return 0
      fi
    done
  done
  # k10temp without labels: temp1_input is usually Tctl.
  for h in /sys/class/hwmon/hwmon*; do
    [[ -r "$h/name" ]] || continue
    read -r nm <"$h/name" 2>/dev/null || continue
    if [[ "$nm" == "k10temp" || "$nm" == "coretemp" ]]; then
      [[ -r "$h/temp1_input" ]] && { echo "$h/temp1_input"; return 0; }
    fi
  done
  echo ""
}
PKG_INPUT="$(detect_pkg_input)"

# millidegrees file -> whole degrees C (or NA)
read_milli_c() {
  local f="$1" v
  [[ -n "$f" && -r "$f" ]] || { echo "NA"; return; }
  read -r v <"$f" 2>/dev/null || { echo "NA"; return; }
  [[ "$v" =~ ^-?[0-9]+$ ]] || { echo "NA"; return; }
  awk -v v="$v" 'BEGIN{printf "%.1f", v/1000.0}'
}

pkg_temp() { read_milli_c "$PKG_INPUT"; }

# Max over all per-core "Core N" coretemp inputs (falls back to NA).
core_max_temp() {
  local best="" h label f v
  for h in /sys/class/hwmon/hwmon*; do
    [[ -r "$h/name" ]] || continue
    read -r nm <"$h/name" 2>/dev/null || continue
    [[ "$nm" == "coretemp" ]] || continue
    for lf in "$h"/temp*_label; do
      [[ -r "$lf" ]] || continue
      read -r label <"$lf" 2>/dev/null || continue
      [[ "$label" == Core* ]] || continue
      f="${lf%_label}_input"
      [[ -r "$f" ]] || continue
      read -r v <"$f" 2>/dev/null || continue
      [[ "$v" =~ ^-?[0-9]+$ ]] || continue
      if [[ -z "$best" || "$v" -gt "$best" ]]; then best="$v"; fi
    done
  done
  if [[ -z "$best" ]]; then
    # No per-core labels (e.g. AMD) — fall back to the package temp.
    pkg_temp; return
  fi
  awk -v v="$best" 'BEGIN{printf "%.1f", v/1000.0}'
}

# First fanN_input across hwmon that is > 0, else NA.
fan_rpm() {
  local h f v
  for h in /sys/class/hwmon/hwmon*; do
    for f in "$h"/fan*_input; do
      [[ -r "$f" ]] || continue
      read -r v <"$f" 2>/dev/null || continue
      [[ "$v" =~ ^[0-9]+$ ]] || continue
      if [[ "$v" -gt 0 ]]; then echo "$v"; return; fi
    done
  done
  echo "NA"
}

load1() {
  local l
  read -r l _ </proc/loadavg 2>/dev/null || { echo "NA"; return; }
  echo "$l"
}

# ---------------------------------------------------------------------------
# iostat: run one 10 s interval and emit, per requested device, the fields:
#   r/s w/s rMBps wMBps util await
# Parsed by column HEADER name so it is robust across sysstat versions
# (await is taken as max(r_await,w_await) when a combined await column is absent).
# Prints lines: "<dev> <r/s> <w/s> <rMBps> <wMBps> <util> <await>"
# ---------------------------------------------------------------------------
iostat_interval() {
  if [[ "$HAVE_IOSTAT" -ne 1 ]]; then
    local dev
    for dev in "${DISK_LIST[@]}"; do echo "$dev NA NA NA NA NA NA"; done
    return
  fi
  LC_ALL=C iostat -x -d -k 10 2 "${DISK_LIST[@]}" 2>/dev/null | awk -v devs="${DISK_LIST[*]}" '
    BEGIN{ n=split(devs,want," "); for(i=1;i<=n;i++) wanted[want[i]]=1 }
    /^Device/ { for(i=1;i<=NF;i++) col[$i]=i; blk++; next }
    NF==0 { next }
    {
      # Keep only the LAST (interval) block per device.
      dev=$1
      if(!(dev in wanted)) next
      rps = (("r/s" in col)   ? $col["r/s"]   : "NA")
      wps = (("w/s" in col)   ? $col["w/s"]   : "NA")
      rk  = (("rkB/s" in col) ? $col["rkB/s"] : "NA")
      wk  = (("wkB/s" in col) ? $col["wkB/s"] : "NA")
      ut  = (("%util" in col) ? $col["%util"] : "NA")
      if("await" in col) aw=$col["await"]
      else {
        ra = (("r_await" in col) ? $col["r_await"] : "")
        wa = (("w_await" in col) ? $col["w_await"] : "")
        if(ra=="" && wa=="") aw="NA"
        else { aw=(ra==""?0:ra); if(wa!="" && wa+0>aw+0) aw=wa }
      }
      last[dev] = rps" "wps" "rk" "wk" "ut" "aw
    }
    END{
      for(i=1;i<=n;i++){
        d=want[i]
        if(d in last){
          split(last[d],a," ")
          rmb = (a[3]=="NA"?"NA":sprintf("%.3f", a[3]/1024.0))
          wmb = (a[4]=="NA"?"NA":sprintf("%.3f", a[4]/1024.0))
          print d, a[1], a[2], rmb, wmb, a[5], a[6]
        } else {
          print d, "NA","NA","NA","NA","NA","NA"
        }
      }
    }'
}

# ---------------------------------------------------------------------------
# SMART: disk temp + Wear/Reallocated/Power_On for one device. Cached per device.
# Prints: "<disk_temp_c> <wear> <reallocated> <power_on_h>"
# ---------------------------------------------------------------------------
smart_read() {
  local dev="$1"
  if [[ "$HAVE_SMARTCTL" -ne 1 || "$dev" == "NA" ]]; then
    echo "NA NA NA NA"; return
  fi
  local out; out="$(smartctl -A "/dev/$dev" 2>/dev/null)"
  [[ -z "$out" ]] && { echo "NA NA NA NA"; return; }
  echo "$out" | awk '
    BEGIN{temp="NA"; wear="NA"; realloc="NA"; poh="NA"}
    # ATA attribute table: ID# ATTRIBUTE_NAME ... RAW_VALUE(last field)
    /Temperature_Celsius/        { temp=$10 }
    /Airflow_Temperature_Cel/    { if(temp=="NA") temp=$10 }
    /Reallocated_Sector_Ct/      { realloc=$10 }
    /Reallocated_Event_Count/    { if(realloc=="NA") realloc=$10 }
    /Power_On_Hours/             { poh=$10 }
    /Wear_Leveling_Count/        { wear=$4 }   # normalized value = remaining life %
    /Media_Wearout_Indicator/    { if(wear=="NA") wear=$4 }
    /Percent_Lifetime_Remain/    { if(wear=="NA") wear=$4 }
    /SSD_Life_Left/              { if(wear=="NA") wear=$4 }
    # NVMe / scsi style "Temperature:" and "Percentage used"
    /^Temperature:/              { if(temp=="NA") temp=$2 }
    /Percentage [Uu]sed/         { gsub(/%/,""); wear=$NF }
    END{
      # strip anything non-numeric-ish from temp (ATA raw can be "41 (Min/Max ...)")
      gsub(/[^0-9.\-].*/,"",temp)
      if(temp=="") temp="NA"
      print temp, wear, realloc, poh
    }'
}

# ---------------------------------------------------------------------------
# CSV header
# ---------------------------------------------------------------------------
write_header() {
  {
    echo "# HW1 sampler — pve01 thermal/disk CSV"
    echo "# generated_at_epoch=$(date +%s) iso=$(date -Is 2>/dev/null || date)"
    echo "# tools: iostat=$([[ $HAVE_IOSTAT -eq 1 ]] && echo yes || echo 'NO (disk fields=NA)') \
smartctl=$([[ $HAVE_SMARTCTL -eq 1 ]] && echo yes || echo 'NO (SMART/disk_temp=NA)') \
sensors=$([[ $HAVE_SENSORS -eq 1 ]] && echo yes || echo 'no (using /sys/class/hwmon)')"
    echo "# pkg_temp_input=${PKG_INPUT:-NONE (pkg_temp=NA)}"
    echo "# disks_monitored=${DISK_LIST[*]}"
    echo "# smart_interval_s=$SMART_INTERVAL_S"
    echo "# NOTE: one row per (timestamp,disk); CPU/thermal columns repeat across a timestamp's disk rows."
    echo "# NOTE: any missing metric is the literal string NA."
    echo "timestamp_epoch,iso,pkg_temp_c,core_max_temp_c,load1,cpu_busy_pct,fan_rpm,disk,r_s,w_s,rMBps,wMBps,util_pct,await_ms,disk_temp_c,smart_wear,smart_reallocated,smart_power_on_h"
  } >>"$OUT"
}

[[ -s "$OUT" ]] || write_header

# Cached SMART values per device (parallel arrays indexed with DISK_LIST).
declare -A SMART_CACHE
SMART_LAST_EPOCH=0

cpu_snapshot() {
  # Print "<total> <idle>" from /proc/stat's aggregate cpu line (jiffies).
  awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6; exit}' /proc/stat 2>/dev/null
}

emit_sample() {
  local base_total base_idle
  read -r base_total base_idle < <(cpu_snapshot)
  [[ -z "${base_total:-}" ]] && { base_total=0; base_idle=0; }

  mapfile -t IO < <(iostat_interval)

  local aft_total aft_idle busy
  read -r aft_total aft_idle < <(cpu_snapshot)
  if [[ -n "${aft_total:-}" && "$base_total" -gt 0 && "${aft_total:-0}" -gt "$base_total" ]]; then
    local dt=$((aft_total-base_total)) di=$((aft_idle-base_idle))
    busy="$(awk -v dt="$dt" -v di="$di" 'BEGIN{printf "%.1f",(dt-di)*100.0/dt}')"
  else
    busy="NA"
  fi

  local epoch iso pkg coremax ld fan
  epoch="$(date +%s)"; iso="$(date -Is 2>/dev/null || date)"
  pkg="$(pkg_temp)"; coremax="$(core_max_temp)"; ld="$(load1)"; fan="$(fan_rpm)"

  if (( epoch - SMART_LAST_EPOCH >= SMART_INTERVAL_S )); then
    local dev
    for dev in "${DISK_LIST[@]}"; do SMART_CACHE[$dev]="$(smart_read "$dev")"; done
    SMART_LAST_EPOCH="$epoch"
  fi

  local row
  for row in "${IO[@]}"; do
    local dev rps wps rmb wmb util await
    read -r dev rps wps rmb wmb util await <<<"$row"
    local sm="${SMART_CACHE[$dev]:-NA NA NA NA}"
    local dtmp wear realloc poh
    read -r dtmp wear realloc poh <<<"$sm"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$epoch" "$iso" "$pkg" "$coremax" "$ld" "$busy" "$fan" \
      "$dev" "$rps" "$wps" "$rmb" "$wmb" "$util" "$await" \
      "$dtmp" "$wear" "$realloc" "$poh" >>"$OUT"
  done
}

if [[ "${SAMPLE_ONCE:-0}" == "1" ]]; then
  emit_sample
  exit 0
fi

# Main loop. iostat's 10 s interval paces us; if iostat is absent, sleep 10 s.
while :; do
  emit_sample
  [[ "$HAVE_IOSTAT" -eq 1 ]] || sleep 10
done
