"""scripts/ci/mq_slim.py -- MQ-TEST-SLIM-1 levers for select-affected.py.

Two levers that would make a merge-queue round run less, computed here and, in
shadow mode (the default), only LOGGED: select-affected.py's mode, legs and
existing gate_* outputs are byte-identical with or without this module.

  testreach  A package that rule 2 (a non-Go file in its directory) or rule 3
             (a literal naming a changed file) selected, and that no changed Go
             code reaches, does not need all its tests: only those whose static
             reach can observe the changed file (scripts/ci/testreach). 43% of
             the selected leg-minutes of 60 rounds (10-13 Nov 2026) were such
             packages (report SESSION-MQ-TEST-SLIM-1, section 3).
  gate       edge-builds, e2e-smoke and smoke build and run the shipped
             binaries; when no code seed reaches them and their harness is
             untouched, their result cannot differ from the base's.

Switch: MQ_SLIM_MODE = off | shadow | enforce (default shadow). off computes
nothing. shadow and enforce compute and log one line per decision on stderr:
  MQ-SHADOW {"v":1,"lever":...,"check":...,"decision":...,...}
(decision: would-skip | would-narrow | keep | error). Only enforce adds outputs
a workflow can act on (leg_tests, gate_edge, gate_e2e_smoke, gate_smoke) and the
sampled full run; ci.yml reads them only when its repository variable says
enforce (patch in the session report). Every failure here is logged as an
"error" record and changes nothing: the caller keeps its own decision.
"""
import json
import os
import re
import subprocess

MODULE = "github.com/keyorixhq/keyorix"
MODES = ("off", "shadow", "enforce")
EDGE_MAINS = (MODULE + "/server", MODULE + "/cmd/keyorix-k8s-sync", MODULE + "/cmd/keyorix-mcp")
READER_SRC = re.compile(r"\bruntime\.Callers?\(|\bos\.Getwd\(")
READER_IMPORTS = {"go/parser", "golang.org/x/tools/go/packages", "os/exec"}
MAX_LOGGED_TESTS = int(os.environ.get("MQ_SLIM_MAX_LOGGED", "40") or "40")
SAMPLE_EVERY = 10


def mode():
    m = os.environ.get("MQ_SLIM_MODE", "shadow").strip().lower() or "shadow"
    return m if m in MODES else "shadow"


def sampled_full_run():
    """enforce only: a merge_group run whose GITHUB_RUN_NUMBER is divisible by
    SAMPLE_EVERY is a full run, the safety net that bounds how long a selection
    miss can stay unseen. The run number counts every run of the workflow (pull
    request and push runs too), so this samples about 1 in SAMPLE_EVERY
    merge_group runs at random, not exactly every SAMPLE_EVERY-th one."""
    if mode() != "enforce" or os.environ.get("GITHUB_EVENT_NAME") != "merge_group":
        return False
    try:
        return int(os.environ.get("GITHUB_RUN_NUMBER", "1")) % SAMPLE_EVERY == 0
    except ValueError:
        return False


def _context():
    ref = os.environ.get("GITHUB_REF", "")
    m = re.search(r"/pr-(\d+)-", ref)
    return {"run_id": os.environ.get("GITHUB_RUN_ID"), "ref": ref, "pr": int(m.group(1)) if m else None}


def record(log, lever, check, decision, why, **extra):
    rec = {"v": 1, "lever": lever, **_context(), "check": check, "decision": decision, "why": why, "mode": mode(), **extra}
    log(f"MQ-SHADOW {json.dumps(rec, sort_keys=True)}")
    return rec


def link_set(packages, imp):
    """Every package linked into imp's test binary."""
    o = packages[imp]
    out = set(o.get("Deps") or [])
    for q in (o.get("TestImports") or []) + (o.get("XTestImports") or []):
        out.add(q)
        out.update((packages.get(q) or {}).get("Deps") or [])
    return out


def closure(packages, seeds):
    """select-affected.py's rule 4 over the given code seeds."""
    aff = set(seeds)
    for imp, o in packages.items():
        if set(o.get("Deps") or []) & seeds:
            aff.add(imp)
            continue
        t = set((o.get("TestImports") or []) + (o.get("XTestImports") or []))
        if t & seeds or any(seeds & set((packages.get(q) or {}).get("Deps") or []) for q in t):
            aff.add(imp)
    return aff


def readers(packages):
    """In-module packages whose non-test code can read the source tree without
    a literal path, closed over their in-module imports."""
    out = set()
    for imp, o in packages.items():
        if READER_IMPORTS & set(o.get("Imports") or []):
            out.add(imp)
            continue
        for n in o.get("GoFiles") or []:
            try:
                with open(os.path.join(o["Dir"], n), encoding="utf-8", errors="replace") as fh:
                    if READER_SRC.search(fh.read()):
                        out.add(imp)
                        break
            except OSError:
                out.add(imp)
                break
    changed = True
    while changed:
        changed = False
        for imp, o in packages.items():
            if imp not in out and out & set(o.get("Imports") or []):
                out.add(imp)
                changed = True
    return out


def requests(ctx):
    """testreach requests for the narrowable packages, and why the others keep
    all their tests."""
    packages, repo = ctx["packages"], ctx["repo"]
    lit_code = ctx["code_seeds"] - ctx["real_code"]
    real = closure(packages, ctx["real_code"])
    rdr = readers(packages)
    reaching = {p for p, o in packages.items() if p in lit_code or lit_code & set(o.get("Deps") or [])}
    reqs, keep = [], {}
    for imp in sorted(ctx["affected"]):
        if imp in real:
            keep[imp] = "changed Go code reaches it"
            continue
        if imp in ctx["special"]:
            keep[imp] = "selected by a named-reader rule (" + ctx["special"][imp] + ")"
            continue
        o = packages[imp]
        own = set((o.get("Imports") or []) + (o.get("TestImports") or []) + (o.get("XTestImports") or []))
        files = set(ctx["inputs"].get(imp, [])) | set(ctx["hits"].get(imp, []))
        chain = []
        for q in sorted(link_set(packages, imp) & reaching):
            if q == imp or q not in packages:
                continue
            files |= set(ctx["hits"].get(q, [])) if q in lit_code else set()
            chain.append({"dir": os.path.relpath(packages[q]["Dir"], repo),
                          "seed_imports": sorted(set(packages[q].get("Imports") or []) & reaching),
                          "is_seed": q in lit_code})
        if imp in lit_code:
            files |= set(ctx["hits"].get(imp, []))
        rel = os.path.relpath(o["Dir"], repo)
        # The module root's files have dirname "" but relpath ".".
        changed_tests = sorted(f for f in ctx["changed"] if f.endswith("_test.go") and (os.path.dirname(f) or ".") == rel)
        reqs.append({
            "dir": rel,
            "import_path": imp,
            "targets": [{"file": f, "outside": ctx["owner"](f) is None} for f in sorted(files)],
            "test_files": [os.path.basename(f) for f in changed_tests],
            # What a changed test file removed (an init() registry row, a
            # TestMain) is only in its base version; "" when the change adds it.
            "base_test_sources": {os.path.basename(f): ctx["file_at"](ctx["base"], f) for f in changed_tests},
            "seed_imports": sorted(own & reaching),
            "reader_imports": sorted(own & rdr),
            "chain": chain,
        })
    return reqs, keep


def run_testreach(reqs, timeout=180):
    # MQ_SLIM_TESTREACH: a prebuilt binary (replays against older trees, tests).
    cmd = [os.environ["MQ_SLIM_TESTREACH"]] if os.environ.get("MQ_SLIM_TESTREACH") else ["go", "run", "./scripts/ci/testreach"]
    p = subprocess.run(cmd, input=json.dumps(reqs),
                       capture_output=True, text=True, timeout=timeout, check=True)
    return {r["import_path"]: r for r in json.loads(p.stdout)}


def testreach_lever(ctx, legs, leg_pkgs, log):
    """MQ-SHADOW records per selected leg, and (enforce) leg_tests:
    {leg: "-" (skip its tests) | "^(T1|T2)$" (run only these)}."""
    reqs, keep = requests(ctx)
    res = run_testreach(reqs) if reqs else {}
    recs, leg_tests, first_shard = [], {}, {}
    for leg in sorted(legs):
        pkgs = sorted(set(leg_pkgs.get(leg, [])) & ctx["affected"])
        kept = [p for p in pkgs if p in keep or p not in res or res[p]["all"]]
        if kept:
            p = kept[0]
            why = keep.get(p) or (res[p]["reason"] if p in res else "not analysed")
            recs.append(record(log, "testreach", "test-suite/" + leg, "keep", f"{p.replace(MODULE + '/', '')}: {why}"))
            continue
        names = sorted({t for p in pkgs for t in (res[p]["tests"] or [])})
        total = sum(res[p]["total"] for p in pkgs)
        sharded = legs[leg] == "*"
        # A sharded package's narrowed tests all run in its first selected
        # shard: the ci.yml enforce patch must run leg_tests there whatever
        # that shard's weight partition holds (re-check when it is reviewed).
        if sharded and names and first_shard.setdefault(pkgs[0], leg) != leg:
            names_here = []
        else:
            names_here = names
        decision = "would-narrow" if names_here else "would-skip"
        why = "; ".join(f"{p.replace(MODULE + '/', '')}: {res[p]['reason']}" for p in pkgs)
        recs.append(record(log, "testreach", "test-suite/" + leg, decision, why,
                           pkg=",".join(p.replace(MODULE + "/", "") for p in pkgs),
                           run_tests=len(names_here), of_tests=total, tests=names_here[:MAX_LOGGED_TESTS],
                           # mq-shadow-report.py: a failure outside a truncated list is unknown, not a miss.
                           tests_truncated=len(names_here) > MAX_LOGGED_TESTS))
        leg_tests[leg] = "^(" + "|".join(re.escape(n) for n in names_here) + ")$" if names_here else "-"
    return recs, leg_tests


def gate_lever(ctx, gates, touched, log):
    """edge / e2e_smoke / smoke gates, logged against the jobs that would skip.

    Not covered: these decisions use code seeds only. e2e-tagged test files are
    IgnoredGoFiles for the root go list, so rule 3 never indexes their
    literals, and a non-Go, non-embedded file read at run time by an e2e test
    or by the server, outside scripts/e2e/, does not open a gate. Re-check
    before the ci.yml enforce patch lands (REVIEW-4196-DEEP-1 L5)."""
    packages, code = ctx["packages"], ctx["code_seeds"]

    def reaches(main_pkgs):
        for m in main_pkgs:
            o = packages.get(m)
            if o is None or code & ({m} | set(o.get("Deps") or [])):
                return True
        return False

    cli_roots = cli_root_imports(ctx["repo"])
    cli = touched(lambda f: f.startswith("cli/")) or cli_roots is None or reaches(sorted(cli_roots & set(packages)))
    e2e_deps = e2e_tagged_deps()
    # The Go server binary, not docker_boot (that one also opens for web/: the
    # image ships the UI; these three jobs build with the committed webui
    # placeholder, as every ci.yml job does).
    server = reaches([MODULE + "/server"])
    new = {
        "edge": server or cli or reaches(EDGE_MAINS) or touched(lambda f: f.startswith(("migrate/", "operator/", "scripts/edge/"))),
        "e2e_smoke": server or cli or e2e_deps is None or bool(code & e2e_deps) or touched(lambda f: f.startswith("scripts/e2e/") or f == "Makefile"),
        "smoke": server or cli or touched(lambda f: f in ("scripts/smoke.sh", "QUICK_START.md", "Makefile")),
    }
    jobs = {"edge": "edge-builds", "e2e_smoke": "e2e-smoke", "smoke": "smoke"}
    recs = [record(log, "gate", jobs[g], "keep" if on else "would-skip",
                   "its binaries or harness are affected" if on else "no code seed reaches its binaries and its harness is untouched")
            for g, on in new.items()]
    return recs, new


def cli_root_imports(repo):
    """Root-module packages that cli/ imports (cli is its own module, so the
    root go list cannot see it). None when cli/ cannot be read."""
    out, found = set(), False
    pat = re.compile(r'"(' + re.escape(MODULE) + r'/[^"]+)"')
    for d, dirs, files in os.walk(os.path.join(repo, "cli")):
        dirs[:] = [x for x in dirs if x not in ("testdata", "node_modules")]
        for n in files:
            if n.endswith(".go") and not n.endswith("_test.go"):
                found = True
                try:
                    with open(os.path.join(d, n), encoding="utf-8", errors="replace") as fh:
                        out.update(m for m in pat.findall(fh.read()) if not m.startswith(MODULE + "/cli"))
                except OSError:
                    return None
    return out if found else None


def e2e_tagged_deps():
    """Root packages linked into the e2e-tagged scripts/e2e tests (make e2e-smoke
    and e2e-journeys); None on any error (the gate then stays open)."""
    try:
        p = subprocess.run(["go", "list", "-tags", "e2e", "-test", "-deps", "-f", "{{.ImportPath}}", "./scripts/e2e/..."],
                           capture_output=True, text=True, timeout=120, check=True)
    except (subprocess.SubprocessError, OSError):
        return None
    return {line.split(" [", 1)[0] for line in p.stdout.split() if line.startswith(MODULE + "/")}


def run(ctx, legs, leg_pkgs, gates, touched, log):
    """Entry point from select-affected.decide(): (records, outputs). outputs
    is empty unless MQ_SLIM_MODE=enforce."""
    if mode() == "off":
        return [], {}
    recs, out = [], {}
    try:
        r, leg_tests = testreach_lever(ctx, legs, leg_pkgs, log)
        recs += r
        if mode() == "enforce":
            out["leg_tests"] = leg_tests
    except Exception as exc:  # shadow must never change the decision
        recs.append(record(log, "testreach", "test-suite", "error", f"{type(exc).__name__}: {exc}"))
    try:
        r, new = gate_lever(ctx, gates, touched, log)
        recs += r
        if mode() == "enforce":
            out.update({"gate_" + g: on for g, on in new.items()})
    except Exception as exc:
        recs.append(record(log, "gate", "edge-builds,e2e-smoke,smoke", "error", f"{type(exc).__name__}: {exc}"))
    return recs, out
