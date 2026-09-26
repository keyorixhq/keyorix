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

## Not yet covered here (exercised manually during the campaign; good follow-ups)

- Postgres backup/restore (`pg_dump`/`pg_restore`), see RELEASE-QA report step 9.
- Docker Compose / Helm chart boot checks — deliberately NOT added here yet,
  since both currently fail to boot at all (see FINDINGS-inbox.md); a
  `docker compose up -d && curl .../health` / `kind`+`helm install`+wait-for-ready
  smoke script would have caught both immediately and is recommended as a CI
  gate once the underlying defects are fixed, not just as a RELEASE-QA script.
- Bad-day checks (wrong password, server down, disk full, port in use, TLS
  self-signed, clock skew) — ad hoc one-off commands during the campaign, not
  yet scripted into a reusable form.
