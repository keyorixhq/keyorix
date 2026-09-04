#!/usr/bin/env python3
"""matrix_runner.py — read scenarios.tsv, drive real load against a real
keyorix-server container for each row, sample /proc/<pid>/status, and emit
the results as a generated Markdown table (stdout, or --out FILE).

This is what docs/adr-100-mlockall-removal-deployment-swap-control.md's
measurement tables should be regenerated from -- see this directory's
README.md for the full methodology and the portability caveat (numbers are
tied to the host/container-runtime that produced them, not portable as
absolute values across environments).

Usage:
    python3 scripts/memory-measurement/matrix_runner.py
    python3 scripts/memory-measurement/matrix_runner.py --out results.md
    python3 scripts/memory-measurement/matrix_runner.py --only count-50,count-1000

Requires: a working `docker` on PATH, run from anywhere inside the repo
(resolves the repo root via `git rev-parse --show-toplevel`).

Runtime: the full default matrix takes over 30 minutes (the sustained-*
scenario alone is a real 30-minute wall-clock pass by design -- see Step 3
of the #1679 follow-up round this harness was built for). Use --only to run
a subset while iterating.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import container_env  # noqa: E402
import load_driver  # noqa: E402
import proc_status  # noqa: E402

MAIN_CONTAINER = "keyorix-memory-measurement-main"
SIDE_CONTAINER = "keyorix-memory-measurement-side"
MAIN_PORT = 18180
SIDE_PORT = 18181


def read_scenarios(path: str, only: set) -> list:
    rows = []
    with open(path, newline="") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            fields = line.rstrip("\n").split("\t")
            if fields[0] == "id":
                continue  # header line, if present without a leading '#'
            row = dict(zip(
                ["id", "kind", "secret_count", "secret_size", "concurrency",
                 "duration_s", "endpoint", "memory_cap", "description"],
                fields,
            ))
            if only and row["id"] not in only:
                continue
            rows.append(row)
    return rows


def fmt_row(label: str, rss: int, hwm: int, extra: str = "") -> str:
    return f"| {label} | {rss} kB | {hwm} kB | {extra} |"


def run_create_burst(row, client, token, results):
    r = load_driver.create_burst(
        client, token, int(row["secret_count"]), int(row["secret_size"]),
        int(row["concurrency"]), row["id"],
    )
    st = proc_status.sample(MAIN_CONTAINER)
    results.append((row["id"], row["description"], st["VmRSS"], st["VmHWM"],
                     f"{r['succeeded']} ok, {r['failed']} failed, {r['elapsed_s']:.1f}s"))


def run_bulk_endpoint(row, client, token, results):
    r = load_driver.hit_endpoint(client, token, row["endpoint"])
    st = proc_status.sample(MAIN_CONTAINER)
    results.append((row["id"], row["description"], st["VmRSS"], st["VmHWM"],
                     f"{r['bytes']} bytes, {r['elapsed_s']:.2f}s"))


def run_oom_check(row, workdir):
    # Everything from container start onward is inside the try, not just the
    # burst itself: a container capped tightly enough to OOM-kill under load
    # can just as plausibly die while still booting/bootstrapping (e.g. an
    # escalated concurrency row run right after a prior row that already
    # pushed the same image close to its cap) -- an exception at ANY of
    # these steps is this scenario's own finding (the container didn't
    # survive), not a harness crash that should lose every scenario's
    # results that already ran before this row.
    try:
        container_env.run_container(SIDE_CONTAINER, workdir, SIDE_PORT,
                                     memory_cap=row["memory_cap"].replace("Mi", "m"))
        base_url = f"http://localhost:{SIDE_PORT}"
        container_env.wait_healthy(base_url, container=SIDE_CONTAINER)
        client = load_driver.Client(base_url)
        token = container_env.wait_admin_ready(client)
        load_driver.create_burst(client, token, int(row["secret_count"]),
                                  int(row["secret_size"]), int(row["concurrency"]), row["id"])
        st = proc_status.sample(SIDE_CONTAINER)
        killed = proc_status.oom_killed(SIDE_CONTAINER)
        return (row["id"], row["description"], st["VmRSS"], st["VmHWM"], f"OOMKilled={killed}")
    except Exception as e:
        try:
            killed = proc_status.oom_killed(SIDE_CONTAINER)
        except Exception:
            killed = "unknown (container inspect also failed)"
        return (row["id"], row["description"], "-", "-", f"OOMKilled={killed} (failed at: {e})")
    finally:
        container_env.remove_container(SIDE_CONTAINER)


def run_sustained(row, workdir, out_lines):
    container_env.run_container(SIDE_CONTAINER, workdir, SIDE_PORT)
    base_url = f"http://localhost:{SIDE_PORT}"
    container_env.wait_healthy(base_url)
    client = load_driver.Client(base_url)
    token = container_env.wait_admin_ready(client)

    samples = []

    def on_sample(elapsed_s, iterations):
        st = proc_status.sample(SIDE_CONTAINER)
        samples.append((elapsed_s, iterations, st["VmRSS"], st["VmHWM"]))
        print(f"  t+{elapsed_s/60:.1f}min iter={iterations} VmRSS={st['VmRSS']}kB VmHWM={st['VmHWM']}kB",
              file=sys.stderr)

    r = load_driver.sustained_mixed_load(
        client, token, int(row["concurrency"]), int(row["duration_s"]), on_sample=on_sample,
    )
    st_end = proc_status.sample(SIDE_CONTAINER)
    container_env.remove_container(SIDE_CONTAINER)

    out_lines.append(f"\n### {row['id']}: {row['description']}\n")
    out_lines.append("| t | iterations | VmRSS | VmHWM (peak) |")
    out_lines.append("|---|---|---|---|")
    for elapsed_s, iterations, rss, hwm in samples:
        out_lines.append(f"| +{elapsed_s/60:.1f}min | {iterations} | {rss} kB | {hwm} kB |")
    out_lines.append(f"| end ({r['elapsed_s']/60:.1f}min) | {r['iterations']} | {st_end['VmRSS']} kB | {st_end['VmHWM']} kB |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="write generated Markdown here instead of stdout")
    ap.add_argument("--only", default=None, help="comma-separated scenario ids to run")
    ap.add_argument("--skip-build", action="store_true", help="reuse an already-built image")
    args = ap.parse_args()

    only = set(args.only.split(",")) if args.only else set()
    scenarios_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios.tsv")
    rows = read_scenarios(scenarios_path, only)
    if not rows:
        print("no scenarios matched", file=sys.stderr)
        sys.exit(1)

    if not args.skip_build:
        print("building server image...", file=sys.stderr)
        container_env.build_image()

    main_workdir = container_env.Workdir()
    side_workdir = container_env.Workdir()
    table_rows = []
    sustained_sections = []

    try:
        main_started = False
        main_client = None
        main_token = None

        for row in rows:
            print(f"=> {row['id']} ({row['kind']})", file=sys.stderr)

            # Each row is caught individually (except oom_check, which
            # already handles its own failure as a FINDING, not an error --
            # a container that dies is exactly what that scenario kind is
            # testing for). A scenario failing partway through must not
            # discard every OTHER scenario's already-collected results --
            # confirmed the hard way: oom-200-2m-512m's container failed to
            # become healthy in an early run of this harness (the prior
            # row's 512Mi-capped container had just been pushed close to
            # its limit) and an uncaught exception there lost all 13
            # already-successful rows before it, with nothing written.
            try:
                if row["kind"] in ("create_burst", "bulk_endpoint"):
                    if not main_started:
                        container_env.run_container(MAIN_CONTAINER, main_workdir, MAIN_PORT)
                        container_env.wait_healthy(f"http://localhost:{MAIN_PORT}", container=MAIN_CONTAINER)
                        main_client = load_driver.Client(f"http://localhost:{MAIN_PORT}")
                        main_token = container_env.wait_admin_ready(main_client)
                        main_started = True
                    if row["kind"] == "create_burst":
                        run_create_burst(row, main_client, main_token, table_rows)
                    else:
                        run_bulk_endpoint(row, main_client, main_token, table_rows)

                elif row["kind"] == "oom_check":
                    side_workdir.reset_data()
                    table_rows.append(run_oom_check(row, side_workdir))

                elif row["kind"] == "sustained":
                    side_workdir.reset_data()
                    run_sustained(row, side_workdir, sustained_sections)

                else:
                    print(f"unknown scenario kind {row['kind']!r} for {row['id']}", file=sys.stderr)
            except Exception as e:
                print(f"!! {row['id']} failed, continuing with remaining scenarios: {e}", file=sys.stderr)
                table_rows.append((row["id"], row["description"], "-", "-", f"SCENARIO FAILED: {e}"))

        lines = [
            f"<!-- generated by scripts/memory-measurement/matrix_runner.py on {time.strftime('%Y-%m-%d %H:%M:%S %Z')} -->",
            "",
            "| Scenario | Description | VmRSS | VmHWM (peak) | Notes |",
            "|---|---|---|---|---|",
        ]
        for row_id, desc, rss, hwm, notes in table_rows:
            lines.append(f"| {row_id} | {desc} | {rss} kB | {hwm} kB | {notes} |")
        lines.extend(sustained_sections)
        output = "\n".join(lines) + "\n"

        if args.out:
            with open(args.out, "w") as f:
                f.write(output)
            print(f"wrote {args.out}", file=sys.stderr)
        else:
            print(output)

    finally:
        container_env.remove_container(MAIN_CONTAINER)
        container_env.remove_container(SIDE_CONTAINER)
        main_workdir.cleanup()
        side_workdir.cleanup()


if __name__ == "__main__":
    main()
