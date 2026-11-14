#!/usr/bin/env python3
"""scripts/ci/mq-shadow-report.py -- evidence for promoting an MQ-TEST-SLIM-1
lever from shadow to enforce (see scripts/ci/mq_slim.py).

For each merge_group run of workflow CI: the MQ-SHADOW records of its `select`
job, matched against what really happened in the same run (every job still
ran: shadow skips nothing). A MISS is
  - a test-suite leg the shadow marked would-skip that FAILED, or
  - a test that failed in a leg the shadow marked would-narrow, and that is
    not among the tests the shadow would have run, or
  - a gated job (edge-builds, e2e-smoke, smoke) marked would-skip that FAILED.
A failure of a test the shadow would have run is not a miss.

A would-skip or would-narrow check whose leg or job did not finish with
success or failure (cancelled -- the merge_group test-suite matrix is
fail-fast, so the first failing leg cancels its siblings --, timed_out,
skipped, or no such job) is INCONCLUSIVE: it might have failed, so the run
proves nothing about that check. So is a would-narrow leg whose failed tests
are not all in a logged test list that mq_slim truncated. A run with an
inconclusive check is not counted as a selected round. Without this the rounds
that carry signal (something failed) would count a miss only when the
narrowed leg happened to fail first, biasing the evidence towards zero misses.

Promotion rule (report SESSION-MQ-TEST-SLIM-1, section 5): >= 7 days, >= 40
conclusive selected rounds, zero misses AND zero inconclusive runs (look at
each INCONCLUSIVE run, e.g. re-run it, before promoting).

Usage:
  mq-shadow-report.py --since 2026-11-15 [--repo keyorixhq/keyorix]   (uses gh)
  mq-shadow-report.py --logs-dir DIR    (offline: DIR/<run>/select.log and
                                         DIR/<run>/jobs.json [{name, conclusion,
                                         log}], as the online mode saves them
                                         with --save DIR)
Exit status: 0 with no misses and no inconclusive run, 1 with misses, 3 with
inconclusive runs but no misses, 2 on a usage or API error.
"""
import argparse
import json
import os
import re
import subprocess
import sys

FAIL_RX = re.compile(r"^\s*--- FAIL: (\S+)", re.M)
JOB_OF = {"edge-builds": "edge-builds", "e2e-smoke": "e2e-smoke", "smoke": "smoke"}
CONCLUSIVE = ("success", "failure")


def gh(*args):
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)}: {p.stderr.strip()[:300]}")
    return p.stdout


def shadow_records(log_text):
    out = []
    for line in log_text.splitlines():
        i = line.find("MQ-SHADOW ")
        if i < 0:
            continue
        try:
            out.append(json.loads(line[i + len("MQ-SHADOW "):]))
        except ValueError:
            continue
    return out


def failed_tests(log_text):
    """Top-level test names that failed (subtests count as their parent)."""
    return {m.split("/", 1)[0] for m in FAIL_RX.findall(log_text or "")}


def leg_of(job_name):
    m = re.match(r"test-suite \(([a-z0-9-]+)[,)]", job_name)
    return m.group(1) if m else None


def judge(records, jobs):
    """(misses, inconclusive, counts) for one run. jobs: [{name, conclusion, log}]."""
    by_leg = {leg_of(j["name"]): j for j in jobs if leg_of(j["name"])}
    by_name = {j["name"]: j for j in jobs}
    misses, inconclusive, counts = [], [], {}

    def finished(check, j):
        """True when j ran to success or failure; else records why not."""
        c = (j or {}).get("conclusion")
        if c in CONCLUSIVE:
            return True
        inconclusive.append({"check": check, "why": f"job conclusion {c}" if j else "no such job in the run"})
        return False

    for r in records:
        counts[r.get("decision")] = counts.get(r.get("decision"), 0) + 1
        check, dec = r.get("check", ""), r.get("decision")
        if dec not in ("would-skip", "would-narrow"):
            continue
        if check.startswith("test-suite/"):
            j = by_leg.get(check.split("/", 1)[1])
            if not finished(check, j) or j.get("conclusion") != "failure":
                continue
            failed = failed_tests(j.get("log", ""))
            if dec == "would-skip":
                misses.append({"check": check, "why": "leg failed but the shadow would have skipped it", "failed": sorted(failed)})
            else:
                logged = r.get("tests") or []
                outside = sorted(failed - set(logged))
                truncated = r.get("tests_truncated") or (r.get("run_tests") or 0) > len(logged)
                if outside and truncated:
                    inconclusive.append({"check": check, "why": "failed tests not in the logged (truncated) narrowed set", "failed": outside})
                elif outside or not failed:
                    misses.append({"check": check, "why": "failed tests outside the narrowed set" if outside else "leg failed, no test name found",
                                   "failed": outside or ["<unknown>"]})
        elif check in JOB_OF and dec == "would-skip":
            j = by_name.get(JOB_OF[check])
            if finished(check, j) and j.get("conclusion") == "failure":
                misses.append({"check": check, "why": "job failed but the shadow would have skipped it"})
    return misses, inconclusive, counts


def online(args):
    q = f"repos/{args.repo}/actions/workflows/ci.yml/runs?event=merge_group&created=>={args.since}&per_page=100"
    runs = json.loads(gh("api", "--paginate", "--slurp", q))
    for page in runs:
        for run in page.get("workflow_runs", []):
            if run.get("status") != "completed":
                continue
            rid = run["id"]
            jobs = []
            for p in json.loads(gh("api", "--paginate", "--slurp", f"repos/{args.repo}/actions/runs/{rid}/jobs?per_page=100")):
                jobs += p.get("jobs", [])
            sel = next((j for j in jobs if j["name"] == "select"), None)
            if not sel:
                continue
            sel_log = gh("api", f"repos/{args.repo}/actions/jobs/{sel['id']}/logs")
            out = []
            for j in jobs:
                log = gh("api", f"repos/{args.repo}/actions/jobs/{j['id']}/logs") if j.get("conclusion") == "failure" else ""
                out.append({"name": j["name"], "conclusion": j.get("conclusion"), "log": log})
            if args.save:
                d = os.path.join(args.save, str(rid))
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "select.log"), "w") as fh:
                    fh.write(sel_log)
                with open(os.path.join(d, "jobs.json"), "w") as fh:
                    json.dump(out, fh)
            yield rid, shadow_records(sel_log), out


def offline(args):
    for rid in sorted(os.listdir(args.logs_dir)):
        d = os.path.join(args.logs_dir, rid)
        try:
            with open(os.path.join(d, "select.log")) as fh:
                recs = shadow_records(fh.read())
            with open(os.path.join(d, "jobs.json")) as fh:
                jobs = json.load(fh)
        except OSError:
            continue
        yield rid, recs, jobs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since")
    ap.add_argument("--repo", default="keyorixhq/keyorix")
    ap.add_argument("--logs-dir")
    ap.add_argument("--save")
    args = ap.parse_args()
    if not args.since and not args.logs_dir:
        ap.error("--since or --logs-dir is required")
    try:
        runs = list(offline(args) if args.logs_dir else online(args))
    except RuntimeError as exc:
        print(f"mq-shadow-report: {exc}", file=sys.stderr)
        return 2
    total, all_misses, all_inconclusive, rounds, inconclusive_runs = {}, [], [], 0, 0
    for rid, recs, jobs in runs:
        if not recs:
            continue
        misses, inconclusive, counts = judge(recs, jobs)
        if inconclusive:
            inconclusive_runs += 1
        else:
            rounds += 1
        for k, v in counts.items():
            total[k] = total.get(k, 0) + v
        for m in misses:
            all_misses.append({"run": rid, **m})
        for m in inconclusive:
            all_inconclusive.append({"run": rid, **m})
    print(f"mq-shadow-report: {rounds} conclusive runs with shadow records, {inconclusive_runs} inconclusive; "
          f"decisions {json.dumps(total, sort_keys=True)}; misses {len(all_misses)}; inconclusive checks {len(all_inconclusive)}")
    for m in all_misses:
        print("MISS " + json.dumps(m, sort_keys=True))
    for m in all_inconclusive:
        print("INCONCLUSIVE " + json.dumps(m, sort_keys=True))
    if all_misses:
        return 1
    return 3 if all_inconclusive else 0


if __name__ == "__main__":
    sys.exit(main())
