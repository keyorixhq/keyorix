# scripts/release-qa/

Reusable harness scripts for exercising a real, built `keyorix`/`keyorix-server`
against the RELEASE-QA track's scenario matrix (see the track's own report,
`~/proj/prompts/reports/RELEASE-QA.md`, for the full campaign this was built for).
Each script drives real binaries end-to-end over HTTP — no mocks, no unit-test
harness — so it exercises exactly what an operator or `docker`/`kind` container
would run.

## scenario1.sh

Fresh install → admin init → start → login → project → secret create/get/export →
machine identity token → app read → revoke → denied.

```
scenario1.sh <server-bin> <cli-bin> [work-dir]
```

- SQLite by default. Set `KEYORIX_QA_STORAGE=postgres` and `KEYORIX_QA_PG_DSN=<dsn>`
  to run against Postgres instead.
- `KEYORIX_QA_PORT` overrides the server port (default 18089).
- Contains a documented workaround for a real gap found while building this
  harness: no `keyorix` CLI command grants a machine identity a project role
  (see the script's own inline `NOTE` and the RELEASE-QA report / FINDINGS-inbox
  for the full writeup) — the script calls the underlying HTTP endpoint directly
  so the rest of the scenario can be exercised. Remove that workaround once a
  real CLI command exists.
- Works unmodified inside a container (tested: ubuntu:22.04/24.04, debian:12,
  rockylinux:9, alpine:3.24, `docker run --network none` for the air-gapped case)
  as well as directly on a macOS/Linux host — it only needs `bash`, `curl`,
  `python3`, and the two binaries.

## scenario23_sqlite.sh

Scenario 2 (restart survives) + scenario 3 (backup → wipe → restore →
verify-audit → secrets readable), SQLite only — `admin backup`/`admin restore`
refuse non-sqlite storage by design; see `docs/SELF_HOSTING.md` §5 for the
Postgres equivalent (`pg_dump`/`pg_restore`), which was exercised manually during
the campaign this harness came from but isn't yet scripted here (a good next
addition).

```
scenario23_sqlite.sh <server-bin> <cli-bin> [work-dir]
```

## scenario_version_skip_postgres.sh

design-b3-backup-v2.md §11.1/H6's version-skipping upgrade proof: `admin backup`
with a REAL OLD release binary (v0.95.0 or v0.94.0, SQLite — that's all the v1
physical format ever supported), then HEAD gets that data into a REAL, separate
Postgres database, then proves secrets decrypt identically, the audit chain
verifies, and authz answers (both an ALLOWED and a DENIED probe) match what the
old binary computed for the identical stored grants.

```
scenario_version_skip_postgres.sh <old-server-bin> <old-cli-bin> \
    <new-server-bin> <new-cli-bin> <postgres-dsn> [work-dir]
```

- `<postgres-dsn>` must point at an EMPTY, dedicated Postgres database — restore
  refuses a non-empty target by design.
- The OLD binary's `admin backup` writes the v1 (physical, SQLite-only) format —
  v1 archives can only restore into SQLite (design §3.6 decision 3; there is no
  "raw SQLite file bytes" equivalent on Postgres). The script proves the real
  operator procedure this implies: HEAD restores the v1 archive into an
  intermediate SQLite database first, takes a fresh v2 backup of THAT, and
  restores the v2 archive into Postgres — the actual SQLite→Postgres leg.
- Download an old release binary once via `gh release download <version> -R
  keyorixhq/keyorix -p "keyorix-server_<os>_<arch>"` (and the matching
  `keyorix_<os>_<arch>` CLI) — deliberately not automated in this script itself,
  matching COMMON-RULES' "download in the test setup script, not in CI."
- Found and fixed two real bugs while building this harness (both landed as
  their own PRs before this script could pass): `internal/backupfmt`'s NDJSON
  row encoding was silently dropping every `json:"-"`-tagged column (encrypted
  secret values, password hashes, token hashes — present since the format was
  introduced), and Postgres restore never resynced a table's auto-increment
  sequence after loading rows with explicit primary keys (pg_dump/pg_restore's
  own well-known fixup, missing here), which also poisoned the very first
  request against a freshly-restored server with a spurious 401.
- Calls `clear_cli_credentials` before each phase's login — the script
  deliberately reuses the SAME server URL for both the old and new server (it's
  simulating one host upgrading in place), and the CLI caches its session token
  by server URL; without clearing it, the new binary's login can fail against a
  stale cached token from the old binary's session.

## Not yet covered here (exercised manually during the campaign; good follow-ups)

- Docker Compose / Helm chart boot checks — deliberately NOT added here yet,
  since both currently fail to boot at all (see FINDINGS-inbox.md); a
  `docker compose up -d && curl .../health` / `kind`+`helm install`+wait-for-ready
  smoke script would have caught both immediately and is recommended as a CI
  gate once the underlying defects are fixed, not just as a RELEASE-QA script.
- Bad-day checks (wrong password, server down, disk full, port in use, TLS
  self-signed, clock skew) — ad hoc one-off commands during the campaign, not
  yet scripted into a reusable form.
