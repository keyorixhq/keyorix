#!/usr/bin/env python3
"""scripts/ci-test-quick.py -- affected-package selection for the quick
pull_request test tier (.github/workflows/ci.yml's test-quick-root/
test-quick-cli jobs).

The 18-shard -race test-suite matrix (ci.yml) is the real correctness gate,
but it now runs only on merge_group/push/workflow_dispatch/a PR labeled
ci:full -- the merge queue guarantees it runs against the exact merge result
before anything reaches main, so a PR no longer needs to pay its ~37min
median wall-clock on every push. This script picks the minimal package set a
PR's diff can plausibly affect, so `go test -short` on just that set still
gives a PR author real feedback before the merge queue's full run.

Usage: `git diff --name-only ... | ci-test-quick.py <moddir>`, where <moddir>
is "." for the root module or "cli" for the cli/ module (its own go.mod,
excluded from go.work -- see ci.yml's `cli` job). Prints "FULL" on its own
line if a fallback trigger fires (go.mod/go.sum or .github/ changed -- the
dependency graph or the CI wiring itself might have moved; or
internal/testutil/ changed -- test helpers many packages' _test.go files
import only via test-only imports, and a graph bug there is exactly the kind
of thing this fallback exists to not depend on the graph to catch).
Otherwise prints affected package import paths, one per line: every package
containing a changed file, plus every in-repo package that depends on one of
those (`go list -json`'s Deps field is already the transitive closure of a
package's non-test imports, so membership is one check, not a graph walk;
TestImports/XTestImports are direct-only, so one extra hop through Deps of a
test-imported package catches a test file importing something that itself
transitively imports a changed package).
"""
import json
import os
import subprocess
import sys

FALLBACK_EXACT = {"go.mod", "go.sum", "cli/go.mod", "cli/go.sum"}
FALLBACK_PREFIXES = (".github/", "internal/testutil/")


def needs_full_fallback(changed):
    for f in changed:
        if f in FALLBACK_EXACT or f.startswith(FALLBACK_PREFIXES):
            return True
    return False


def load_packages(moddir):
    # cli/ is its own module (own go.mod, deliberately excluded from
    # go.work's `use` directives -- see ci.yml's `cli` job). Without
    # GOWORK=off, `go list` run with cwd=cli/ still walks up and finds the
    # ROOT go.work, which doesn't list cli/ as a member, and fails outright.
    env = dict(os.environ)
    if moddir != ".":
        env["GOWORK"] = "off"
    out = subprocess.run(
        ["go", "list", "-json", "./..."],
        cwd=moddir, capture_output=True, text=True, check=True, env=env,
    ).stdout.strip()
    packages = {}
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(out):
        obj, end = decoder.raw_decode(out, idx)
        packages[obj["ImportPath"]] = obj
        idx = end
        while idx < len(out) and out[idx].isspace():
            idx += 1
    return packages


def main():
    moddir = sys.argv[1]
    changed = [line.strip() for line in sys.stdin if line.strip()]

    if needs_full_fallback(changed):
        print("FULL")
        return

    if moddir == ".":
        # Root module: cli/ and operator/ are separate Go modules with their
        # own jobs (cli, operator) and their own gating -- a change confined
        # to either can't affect the root module's package graph.
        mod_files = [f for f in changed if f.endswith(".go") and not f.startswith("cli/") and not f.startswith("operator/")]
    else:
        prefix = moddir.rstrip("/") + "/"
        mod_files = [f[len(prefix):] for f in changed if f.startswith(prefix) and f.endswith(".go")]

    if not mod_files:
        return  # nothing in this module changed -- nothing to run

    changed_dirs = sorted({f.rsplit("/", 1)[0] if "/" in f else "." for f in mod_files})

    packages = load_packages(moddir)
    dir_to_pkg = {obj.get("Dir", ""): imp for imp, obj in packages.items()}

    changed_pkgs = set()
    for d in changed_dirs:
        abspath = os.path.abspath(os.path.join(moddir, d))
        pkg = dir_to_pkg.get(abspath)
        if pkg:
            changed_pkgs.add(pkg)

    if not changed_pkgs:
        return

    affected = set(changed_pkgs)
    for imp, obj in packages.items():
        if imp in affected:
            continue
        deps = set(obj.get("Deps") or [])
        if deps & changed_pkgs:
            affected.add(imp)
            continue
        test_imports = set((obj.get("TestImports") or []) + (obj.get("XTestImports") or []))
        if test_imports & changed_pkgs:
            affected.add(imp)
            continue
        for q in test_imports:
            if changed_pkgs & set((packages.get(q, {}) or {}).get("Deps") or []):
                affected.add(imp)
                break

    for p in sorted(affected):
        print(p)


if __name__ == "__main__":
    main()
