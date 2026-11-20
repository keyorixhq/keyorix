#!/usr/bin/env python3
# summarize.py — reduce HW1 sampler CSVs to per-cell talk figures.
#
# INPUT
#   A results directory produced by scripts/hw/run-matrix.sh, containing, per
#   cell: <tag>.csv (sampler output), <tag>.events (phase timestamps) and
#   <tag>.workload.tsv (per build+test pass wall time). It also works on a bare
#   directory of *.csv with no .events (the whole CSV is then treated as "load").
#
# OUTPUT
#   - a Markdown table to stdout (and to <dir>/SUMMARY.md)
#   - a flat machine-readable <dir>/SUMMARY.csv
#
# PER CELL it reports, over the LOAD window (events LOAD_START..LOAD_END; the
# cooldown window LOAD_END..CELL_END is summarized separately as *_cool):
#   median temp, p95 temp, peak temp (CPU package), seconds above 80 C,
#   peak/median disk temp, total MB written, median & peak %util, median await,
#   and the workload wall time (median & p95 of one build+test pass).
#
# Every figure is computed from the CSV rows (not estimated). Missing metrics are
# the literal "NA" in the CSV and are skipped (not counted as 0). What this does
# NOT do: it does not attribute causation, does not model steady-state vs
# transient, and treats each disk row independently (MB written is summed across
# a timestamp's disk rows; CPU stats are de-duplicated per timestamp).
#
# Standard library only (csv, os, sys, glob, statistics). No third-party deps.

import csv
import glob
import os
import statistics
import sys


def pctl(xs, p):
    """Linear-interpolated percentile of a sorted-able list; None if empty."""
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    frac = k - lo
    return xs[lo] * (1 - frac) + xs[hi] * frac


def fnum(s):
    """Parse a CSV field to float, or None for NA/blank/garbage."""
    if s is None:
        return None
    s = s.strip()
    if s == "" or s.upper() == "NA":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def read_events(path):
    ev = {}
    if not os.path.exists(path):
        return ev
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                ev[k.strip()] = v.strip()
    return ev


def read_workload(path):
    """Return list of per-pass wall seconds (rc==0 passes only) + count of fails."""
    walls, fails = [], 0
    if not os.path.exists(path):
        return walls, fails
    with open(path) as fh:
        r = csv.reader(fh, delimiter="\t")
        header = next(r, None)
        for row in r:
            if len(row) < 4:
                continue
            w = fnum(row[2])
            rc = row[3].strip()
            if rc != "0":
                fails += 1
            if w is not None:
                walls.append(w)
    return walls, fails


def load_rows(path):
    """Yield dict rows from a sampler CSV, skipping # comment/header lines."""
    with open(path) as fh:
        reader = csv.reader(fh)
        header = None
        for row in reader:
            if not row:
                continue
            if row[0].startswith("#"):
                continue
            if header is None:
                header = row
                continue
            if len(row) < len(header):
                continue
            yield dict(zip(header, row))


def summarize_window(rows):
    """Compute stats over a list of parsed sampler rows (one window)."""
    # CPU/thermal metrics are per-timestamp; de-duplicate by timestamp_epoch.
    cpu_by_ts = {}
    disk_util, disk_await, disk_temps = [], [], []
    wmb_by_ts = {}  # sum MB/s written across disks per timestamp
    interval_guess = 10.0
    ts_sorted = []
    for d in rows:
        ts = d.get("timestamp_epoch", "")
        pkg = fnum(d.get("pkg_temp_c"))
        if ts not in cpu_by_ts:
            cpu_by_ts[ts] = pkg
            ts_sorted.append(ts)
        util = fnum(d.get("util_pct"))
        if util is not None:
            disk_util.append(util)
        aw = fnum(d.get("await_ms"))
        if aw is not None:
            disk_await.append(aw)
        dtm = fnum(d.get("disk_temp_c"))
        if dtm is not None:
            disk_temps.append(dtm)
        wmb = fnum(d.get("wMBps"))
        if wmb is not None:
            wmb_by_ts[ts] = wmb_by_ts.get(ts, 0.0) + wmb

    temps = [t for t in cpu_by_ts.values() if t is not None]

    # Estimate the sample interval from consecutive timestamps (fallback 10 s).
    tss = sorted(int(t) for t in ts_sorted if t.isdigit())
    if len(tss) >= 2:
        deltas = [b - a for a, b in zip(tss, tss[1:]) if 0 < b - a < 120]
        if deltas:
            interval_guess = statistics.median(deltas)

    # MB written total = sum over timestamps of (MB/s * interval).
    mb_written = sum(v * interval_guess for v in wmb_by_ts.values())
    secs_over_80 = sum(interval_guess for t in temps if t >= 80.0)

    return {
        "n_samples": len(temps),
        "temp_median": statistics.median(temps) if temps else None,
        "temp_p95": pctl(temps, 95),
        "temp_peak": max(temps) if temps else None,
        "secs_over_80": secs_over_80 if temps else None,
        "disk_temp_median": statistics.median(disk_temps) if disk_temps else None,
        "disk_temp_peak": max(disk_temps) if disk_temps else None,
        "util_median": statistics.median(disk_util) if disk_util else None,
        "util_peak": max(disk_util) if disk_util else None,
        "await_median": statistics.median(disk_await) if disk_await else None,
        "mb_written": mb_written,
        "interval_s": interval_guess,
    }


def split_windows(rows, ev):
    """Partition rows into (load, cool) by LOAD_START/LOAD_END/CELL_END."""
    ls = ev.get("LOAD_START")
    le = ev.get("LOAD_END")
    ce = ev.get("CELL_END") or ev.get("ABORTED")
    load, cool = [], []
    if not ls:
        return rows, []  # no events: treat all as load
    ls = int(ls)
    le = int(le) if le else None
    ce = int(ce) if ce else None
    for d in rows:
        ts = d.get("timestamp_epoch", "")
        if not ts.isdigit():
            continue
        t = int(ts)
        if t < ls:
            continue
        if le is None or t <= le:
            load.append(d)
        elif ce is None or t <= ce:
            cool.append(d)
    return load, cool


def fmt(v, nd=1):
    if v is None:
        return "NA"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def main():
    if len(sys.argv) < 2:
        print("usage: summarize.py <results_dir>", file=sys.stderr)
        return 2
    d = sys.argv[1]
    csvs = sorted(glob.glob(os.path.join(d, "*.csv")))
    csvs = [c for c in csvs if os.path.basename(c) != "SUMMARY.csv"]
    if not csvs:
        print(f"no *.csv in {d}", file=sys.stderr)
        return 1

    cells = []
    for c in csvs:
        tag = os.path.basename(c)[:-4]
        ev = read_events(os.path.join(d, tag + ".events"))
        rows = list(load_rows(c))
        load_rows_, cool_rows = split_windows(rows, ev)
        load = summarize_window(load_rows_)
        cool = summarize_window(cool_rows) if cool_rows else None
        walls, fails = read_workload(os.path.join(d, tag + ".workload.tsv"))
        cells.append({
            "tag": tag,
            "storage": ev.get("STORAGE", "?"),
            "N": ev.get("N", "?"),
            "aborted": "ABORTED" in ev,
            "load": load,
            "cool": cool,
            "wall_median": statistics.median(walls) if walls else None,
            "wall_p95": pctl(walls, 95),
            "wall_passes": len(walls),
            "wall_fails": fails,
        })

    # Markdown table.
    cols = [
        ("cell", lambda x: x["tag"]),
        ("stor", lambda x: x["storage"]),
        ("N", lambda x: x["N"]),
        ("abort", lambda x: "YES" if x["aborted"] else ""),
        ("temp_med", lambda x: fmt(x["load"]["temp_median"])),
        ("temp_p95", lambda x: fmt(x["load"]["temp_p95"])),
        ("temp_peak", lambda x: fmt(x["load"]["temp_peak"])),
        ("s>80C", lambda x: fmt(x["load"]["secs_over_80"], 0)),
        ("dtemp_peak", lambda x: fmt(x["load"]["disk_temp_peak"])),
        ("MB_writ", lambda x: fmt(x["load"]["mb_written"], 0)),
        ("util_med", lambda x: fmt(x["load"]["util_median"])),
        ("util_peak", lambda x: fmt(x["load"]["util_peak"])),
        ("await_med", lambda x: fmt(x["load"]["await_median"])),
        ("wall_med", lambda x: fmt(x["wall_median"])),
        ("wall_p95", lambda x: fmt(x["wall_p95"])),
        ("passes", lambda x: str(x["wall_passes"])),
        ("cool_peak", lambda x: fmt(x["cool"]["temp_peak"]) if x["cool"] else "NA"),
    ]
    header = "| " + " | ".join(c[0] for c in cols) + " |"
    sep = "|" + "|".join("---" for _ in cols) + "|"
    lines = [header, sep]
    for x in cells:
        lines.append("| " + " | ".join(c[1](x) for c in cols) + " |")
    md = "\n".join(lines)

    notes = (
        "\nNotes:\n"
        "- temp_* = CPU package temperature (C) over the LOAD window; "
        "cool_peak = peak package temp during the cooldown window.\n"
        "- s>80C = seconds the package temp was >= 80 C (interval-weighted).\n"
        "- MB_writ = total MB written over the LOAD window (sum of per-disk "
        "MB/s * sample interval).\n"
        "- wall_* = wall-clock seconds for ONE go build + go test pass of "
        "the core package under that cell's storage/concurrency.\n"
        "- Figures come only from the CSV. Blank cell = metric was NA "
        "(tool/source absent) for the whole window.\n"
    )

    out_md = os.path.join(d, "SUMMARY.md")
    with open(out_md, "w") as fh:
        fh.write("# HW1 matrix summary\n\n" + md + "\n" + notes)

    # Flat CSV.
    out_csv = os.path.join(d, "SUMMARY.csv")
    with open(out_csv, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "cell", "storage", "N", "aborted",
            "temp_median_c", "temp_p95_c", "temp_peak_c", "secs_over_80c",
            "disk_temp_median_c", "disk_temp_peak_c",
            "mb_written", "util_median", "util_peak", "await_median_ms",
            "wall_median_s", "wall_p95_s", "wall_passes", "wall_fails",
            "cooldown_peak_c", "load_samples",
        ])
        for x in cells:
            L, C = x["load"], x["cool"]
            w.writerow([
                x["tag"], x["storage"], x["N"], x["aborted"],
                fmt(L["temp_median"]), fmt(L["temp_p95"]), fmt(L["temp_peak"]),
                fmt(L["secs_over_80"], 0),
                fmt(L["disk_temp_median"]), fmt(L["disk_temp_peak"]),
                fmt(L["mb_written"], 1), fmt(L["util_median"]),
                fmt(L["util_peak"]), fmt(L["await_median"]),
                fmt(x["wall_median"]), fmt(x["wall_p95"]),
                x["wall_passes"], x["wall_fails"],
                fmt(C["temp_peak"]) if C else "NA", L["n_samples"],
            ])

    print(md)
    print(notes)
    print(f"\nwrote {out_md} and {out_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
