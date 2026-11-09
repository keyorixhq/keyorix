"""Shard layout for the weights tooling, taken from the repo's own bash.

scripts/ci-test-legs.sh is the single source of the matrix (sharded_legs) and of
the assignment (weighted_shard_assignment). This module only calls those two
functions through `bash -c 'source scripts/ci-test-legs.sh; ...'`; it has no
second bin-packer, so a change of the packing rule is seen here without an edit.
Used by check-weights-drift.py and logs-to-timings.py.
"""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LEGS_SH = os.path.join(ROOT, "scripts", "ci-test-legs.sh")
MODULE = "github.com/keyorixhq/keyorix/"


def _bash(script, args=(), stdin="", weights=None):
    env = dict(os.environ)
    if weights:
        env["CI_TEST_WEIGHTS_FILE"] = os.path.abspath(weights)
    proc = subprocess.run(
        ["bash", "-c", f"source {LEGS_SH}\n{script}", "_", *args],
        input=stdin, capture_output=True, text=True, env=env, cwd=ROOT, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"bash {script.split()[0]} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def sharded_packages():
    """{package (module-relative): {"prefix": leg prefix, "shards": n, "preload": str}}
    for every sharded_legs() row with more than one shard (one shard = no split)."""
    out = {}
    rows = _bash('sharded_legs; echo "#pkgs"; while IFS="|" read -r p fn n pre; do '
                 'echo "$p|$($fn)"; done < <(sharded_legs)')
    legs, _, pkgs = rows.partition("#pkgs\n")
    pkg_of = dict(line.split("|", 1) for line in pkgs.splitlines() if "|" in line)
    for line in legs.splitlines():
        prefix, _fn, shards, preload = line.split("|")
        if int(shards) < 2:
            continue
        pkg = pkg_of[prefix].strip().removeprefix(MODULE)
        out[pkg] = {"prefix": prefix, "shards": int(shards), "preload": preload}
    return out


def assign(pkg, shards, preload, names, weights):
    """{test name: shard (1-based)} from weighted_shard_assignment under `weights`."""
    out = _bash('weighted_shard_assignment "$1" "$2" "$3"', (pkg, str(shards), preload),
                stdin="\n".join(names) + "\n", weights=weights)
    return {name: int(shard) for shard, name in (ln.split("\t", 1) for ln in out.splitlines())}


def leg_package(leg):
    """(package, shard number) for a leg name such as faultops-4, or None."""
    prefix, _, num = leg.rpartition("-")
    for pkg, info in sharded_packages().items():
        if info["prefix"] == prefix and num.isdigit() and 1 <= int(num) <= info["shards"]:
            return pkg, int(num)
    return None


def read_weights(path):
    """({package: {test: weight}}, {package: default weight}); explicit rows only in the first."""
    rows, default = {}, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            pkg, test, weight = line.rstrip("\n").split("\t")[:3]
            if test == "*":
                default[pkg] = float(weight)
            else:
                rows.setdefault(pkg, {})[test] = float(weight)
    return rows, default
