#!/usr/bin/env python3
"""THROWAWAY (CI-CACHE-SPIKE-1): summarise a `go -debug-actiongraph` dump.

An action with a non-null Cmd ran (a cache miss); a build action without one
was served from GOCACHE (a hit). Seconds are summed per action (TimeStart to
TimeDone), so they are CPU-ish totals across -p workers, not wall time.
"""
import datetime
import json
import sys

MOD = "github.com/keyorixhq/keyorix"


def ts(s):
    # RFC3339 with up to 9 fractional digits; Python takes 6.
    if "." in s:
        head, rest = s.split(".", 1)
        frac = "".join(c for c in rest if c.isdigit())
        tz = rest[len(frac):]
        s = f"{head}.{frac[:6]}{tz}"
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def kind(pkg):
    p = pkg.split(" ")[0]
    if p.startswith(MOD):
        return "repo"
    first = p.split("/")[0]
    return "ext" if "." in first else "std"


path, label, leg, wall, size_mb = sys.argv[1:6]
acts = json.load(open(path))
out = {"label": label, "leg": leg, "wall_s": round(float(wall), 1), "gocache_mb": int(size_mb)}
for mode in ("build", "vet", "link"):
    sel = [a for a in acts if a.get("Mode") == mode]
    ran = [a for a in sel if a.get("Cmd") is not None]
    out[f"{mode}_total"] = len(sel)
    out[f"{mode}_ran"] = len(ran)
    secs = {"repo": 0.0, "ext": 0.0, "std": 0.0}
    cnt = {"repo": 0, "ext": 0, "std": 0}
    tot = {"repo": 0, "ext": 0, "std": 0}
    for a in sel:
        tot[kind(a.get("Package", ""))] += 1
    for a in ran:
        k = kind(a.get("Package", ""))
        cnt[k] += 1
        if a.get("TimeStart") and a.get("TimeDone"):
            secs[k] += (ts(a["TimeDone"]) - ts(a["TimeStart"])).total_seconds()
    if mode == "build":
        for k in secs:
            out[f"build_{k}_ran"] = f"{cnt[k]}/{tot[k]}"
            out[f"build_{k}_s"] = round(secs[k], 1)
    else:
        out[f"{mode}_s"] = round(sum(secs.values()), 1)
total = out["build_total"]
out["hit_rate"] = round(1 - out["build_ran"] / total, 3) if total else None
print("SPIKE|" + "|".join(f"{k}={v}" for k, v in out.items()))
