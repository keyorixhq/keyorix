#!/usr/bin/env python3
"""Measure package growth for the architecture-growth guard.

Run by scripts/ci/check-growth-guards.sh (check) and by hand (--table) to
regenerate the baseline in docs/design/architecture-growth-baseline.md.

For every package of the root module under internal/ and server/ it reports:
  files       non-test .go files (GoFiles + CgoFiles)
  loc         lines in those files
  dependents  packages of the root module that transitively import it
              (the reverse of `go list -deps ./...`, test imports excluded)

cli/ and operator/ are separate Go modules and are not measured.
"""
import argparse
import json
import os
import subprocess
import sys

MEASURED = ("internal/", "server/")
MEASURED_EXACT = ("server",)  # server/main.go is a package too


def go_list(root):
    out = subprocess.run(
        ["go", "list", "-json=ImportPath,Dir,GoFiles,CgoFiles,Imports,Deps", "./..."],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout
    dec = json.JSONDecoder()
    pkgs, i = [], 0
    while i < len(out):
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            break
        obj, i = dec.raw_decode(out, i)
        pkgs.append(obj)
    return pkgs


def module_path(root):
    return subprocess.run(
        ["go", "list", "-m"], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def count_lines(path):
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def measure(root):
    mod = module_path(root)
    pkgs = go_list(root)
    inmod = {p["ImportPath"] for p in pkgs}
    dependents = {ip: set() for ip in inmod}
    for p in pkgs:
        for d in p.get("Deps") or []:
            if d in dependents and d != p["ImportPath"]:
                dependents[d].add(p["ImportPath"])
    rows = []
    for p in pkgs:
        rel = p["ImportPath"][len(mod) + 1:] if p["ImportPath"] != mod else "."
        if not (rel.startswith(MEASURED) or rel in MEASURED_EXACT):
            continue
        files = (p.get("GoFiles") or []) + (p.get("CgoFiles") or [])
        loc = sum(count_lines(os.path.join(p["Dir"], f)) for f in files)
        rows.append({"pkg": rel, "files": len(files), "loc": loc,
                     "dependents": len(dependents[p["ImportPath"]])})
    return rows


def check(rows, max_files, max_dependents):
    """Return one failure message per package over a ceiling (worst first)."""
    fails = []
    for metric, ceiling, unit in (("files", max_files, "non-test .go files"),
                                  ("dependents", max_dependents, "transitive dependents")):
        for r in sorted(rows, key=lambda r: -r[metric]):
            if r[metric] > ceiling:
                over = r[metric] - ceiling
                fails.append(
                    f"FAIL {r['pkg']}: {r[metric]} {unit}, ceiling {ceiling} "
                    f"(over by {over}, {100 * over / ceiling:.1f}%)")
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--json", action="store_true", help="print the measurement as JSON")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 and name every package over --max-files / --max-dependents")
    ap.add_argument("--max-files", type=int)
    ap.add_argument("--max-dependents", type=int)
    ap.add_argument("--table", metavar="METRIC", choices=["files", "loc", "dependents"],
                    help="print a markdown table sorted by METRIC, descending")
    ap.add_argument("--top", type=int, default=0, help="with --table: only the top N rows")
    a = ap.parse_args()
    rows = measure(a.root)
    if a.check:
        if a.max_files is None or a.max_dependents is None:
            ap.error("--check needs --max-files and --max-dependents")
        fails = check(rows, a.max_files, a.max_dependents)
        worst_f = max(rows, key=lambda r: r["files"])
        worst_d = max(rows, key=lambda r: r["dependents"])
        print(f"measured {len(rows)} packages under internal/ and server/; "
              f"max files {worst_f['files']} ({worst_f['pkg']}), "
              f"max dependents {worst_d['dependents']} ({worst_d['pkg']})")
        for f in fails:
            print(f)
        sys.exit(1 if fails else 0)
    if a.json:
        json.dump(rows, sys.stdout)
        print()
        return
    if a.table:
        rows.sort(key=lambda r: (-r[a.table], r["pkg"]))
        if a.top:
            rows = rows[: a.top]
        print("| package | files | LOC | dependents |")
        print("|---|---:|---:|---:|")
        for r in rows:
            print(f"| `{r['pkg']}` | {r['files']} | {r['loc']} | {r['dependents']} |")
        return
    ap.error("one of --json or --table is required")


if __name__ == "__main__":
    main()
