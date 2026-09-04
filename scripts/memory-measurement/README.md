# Memory-measurement harness

Regenerates the measurement tables in
[`docs/adr-100-mlockall-removal-deployment-swap-control.md`](../../docs/adr-100-mlockall-removal-deployment-swap-control.md)
against a real `keyorix-server` binary in a real container, driven by real
HTTP calls — not synthetic in-process allocation, and not hand-maintained
prose. Built because the original measurement pass existed only as commands
run once in a session transcript; the numbers could not be regenerated or
independently checked without redoing that work from scratch.

## What this covers

Four scenario shapes, defined as data in [`scenarios.tsv`](scenarios.tsv),
not hardcoded per-scenario Python:

- **`create_burst`** — create N secrets of a given size at a given client
  concurrency. Used for both the secret-count axis (concurrency held at 1)
  and the concurrency axis (count/size held fixed) — see ADR-100's
  "Concurrency is the dominant driver, not count" finding.
- **`bulk_endpoint`** — hit one HTTP endpoint (paginated list, the unbounded
  deployment-wide CSV inventory export, the capped audit-log CSV export) at
  whatever secret count the store currently holds.
- **`oom_check`** — replay a burst against a container capped with
  `docker run --memory`, matching a specific `values.yaml` limit, and check
  `docker inspect .State.OOMKilled` afterward.
- **`sustained`** — mixed create/list/read load at fixed concurrency for a
  fixed wall-clock duration, sampling `/proc/<pid>/status` periodically to
  show whether resident memory plateaus or keeps climbing.

Add a new scenario by adding a row to `scenarios.tsv`; `matrix_runner.py`
does not need to change unless the new scenario needs a genuinely new
*kind* of orchestration (see the file's own header comment for the column
schema).

## Running it

```
python3 scripts/memory-measurement/matrix_runner.py
```

Requires `docker` on `PATH` and enough free disk/memory to build and run the
real `server/Dockerfile` image locally. Run from anywhere inside the repo —
the repo root is resolved via `git rev-parse --show-toplevel`.

- `--out results.md` — write the generated table to a file instead of
  stdout.
- `--only id1,id2` — run a subset of `scenarios.tsv`'s rows (by `id` column)
  instead of the full matrix, useful while iterating on the harness itself
  or re-checking one specific finding.
- `--skip-build` — reuse an already-built `keyorix-server-memory-measurement`
  image instead of rebuilding.

**The full default matrix takes over 30 minutes** — the `sustained-25` row
alone is a real 30-minute wall-clock pass by design (that duration is the
point: a shorter run would not have shown the climb ADR-100 documents). Use
`--only` for anything shorter while developing.

Output is Markdown, formatted to paste directly into ADR-100 (or any other
doc) as a replacement for a stale table — this is meant to make "regenerate
the numbers" a single command, not a research project.

## Portability — these numbers are not absolute

Every number this harness produces is tied to the host and container
runtime that produced it, same as ADR-100 states for the original pass:

- **Container CPU architecture and runtime.** The baseline numbers currently
  in ADR-100 were produced on **OrbStack** (`linux/aarch64`), not stock
  Docker Desktop, not bare metal, and not the `linux/amd64` architecture the
  shipped `ghcr.io/keyorixhq/keyorix-server` image and most production
  Kubernetes nodes actually run. Re-running this harness on a different
  runtime/architecture will produce different absolute numbers — the
  *shape* of the findings (concurrency dominates over row count, sustained
  load doesn't plateau within 30 minutes, a 512Mi cap gets OOM-killed under
  a large concurrent burst) is expected to reproduce; the exact kB figures
  are not.
- **Host CPU/memory pressure from anything else running at measurement
  time** — this harness makes no attempt to pin CPU, disable other
  processes, or otherwise isolate the measurement host. Treat absolute
  numbers as directional unless re-measured on a quiet, dedicated machine.
- **SQLite is the default storage backend measured here.** The `oom_check`
  and `sustained` scenarios' findings (SQLite write-lock contention, WAL
  growth under concurrent load) are specific to the shipped default
  (`storage.type: local`); they do not apply to a Postgres-backed
  deployment, which was out of scope for this harness's first pass.

## Not wired into CI

This is a long-running manual harness (see "Running it" above), not a
per-PR or even nightly check — the sustained scenario alone would blow any
reasonable CI job budget on its own, the same tradeoff this repo already
makes for `scripts/fuzzing/` and `scripts/mutation-testing/` (continuous,
dedicated-box tooling for a similar reason: too slow for CI, too valuable to
skip). Unlike those two, this harness doesn't need a dedicated always-on
box — it's meant to be run by hand before a `values.yaml` resource-sizing
decision, not continuously.

**Follow-up, not done here:** if this needs to run on a schedule later (e.g.
after every resource-sizing-relevant change, or monthly to catch drift),
this repo already has the `workflow_dispatch` (manual trigger from the
Actions tab) pattern established in `.github/workflows/dast.yml` and
`.github/workflows/mis-based-merge-detector.yml` — a
`workflow_dispatch`-triggered job wrapping `matrix_runner.py` would fit that
existing convention. Not added in this pass, since nothing here requires it
yet and an unused workflow is one more thing to keep working.
