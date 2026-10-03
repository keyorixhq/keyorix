# Keyorix golden-path demo script (~20 minutes)

A live, working demo script for a new customer: install, secure first start, an
admin's day-one workflow, a CI-style machine identity, and tamper-evident audit —
verified end to end against a fresh SQLite single-node build of `origin/main`
(DEMO-1, 2026-10-03). "Known rough edges" at the end links every gap this exact
script runs into, found driving it as a stranger would.

This script deliberately uses the SQLite single-binary path (`QUICK_START.md`) —
it's the fastest to stand up live. The PostgreSQL/Docker path
(`docs/SELF_HOSTING.md`) is equivalent for everything shown here except the two
backup-related rough edges noted below, which are Postgres-specific.

## 0. Before you're on stage

```sh
git clone https://github.com/keyorixhq/keyorix.git && cd keyorix
make build
```

Produces `./bin/keyorix` (CLI) and `./bin/keyorix-server` (API server). Keep a
terminal with `./bin` on hand and a browser tab ready.

## 1. First start (~3 min)

```sh
export KEYORIX_MASTER_PASSWORD='choose-a-strong-passphrase'
./bin/keyorix-server admin init --config ./keyorix.yaml
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml

export KEYORIX_BOOTSTRAP_TOKEN='choose-a-bootstrap-token'
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server &

./bin/keyorix system init --server http://localhost:8080 \
  --admin-username admin --admin-email admin@keyorix.local \
  --admin-password 'Correct-Horse-Battery9' \
  --bootstrap-token "$KEYORIX_BOOTSTRAP_TOKEN"
```

Say out loud while it runs: TLS is off in this generated config (loud warning in the
server log, by design, for local dev) — see `docs/CONFIGURATION.md`'s `server.http.tls`
section for turning it on with your own cert, or front it with a proxy, before any
real deployment.

**Generate the admin recovery key right after bootstrap, before anything else:**

```sh
./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

(Needs the server stopped — kill the background `keyorix-server`, run this, restart
it the same way. See known rough edges below.) Save the printed key; it's the only
way back in if every admin is ever locked out.

## 2. Log in, show the dashboard (~2 min)

```sh
./bin/keyorix login --server http://localhost:8080 --username admin --password 'Correct-Horse-Battery9'
```

Open **http://localhost:8080** in the browser, log in with the same credentials.
Walk the dashboard: total secrets, active users, audit events, security status.

Skip MFA enrollment live (My Account -> Security -> Two-Factor Authentication) —
it's currently broken end to end (see rough edges).

## 3. Org structure (~2 min)

In the web UI: **Projects -> New Project** twice (e.g. `backend-api`, `mobile-app`
— `default` already exists with 3 seeded environments). **Access Control -> Groups
-> New Group** twice (e.g. `platform-team`, `mobile-team`).

## 4. A least-privilege user (~2 min)

```sh
./bin/keyorix user create --username alice --email alice@keyorix.local --password 'Nebula-Quartz-742'
./bin/keyorix rbac assign-role --user alice@keyorix.local --role project_viewer --project backend-api
```

Say out loud: alice now holds `project_viewer` on `backend-api` only. **Demo this
via the web UI, not the CLI** — logging in as alice and using `keyorix project
list`/`secret list --project ...` from the CLI currently fails for her even on her
own granted project (see rough edges); the web UI path works.

## 5. Secrets lifecycle (~4 min) — the strongest part of this demo

```sh
./bin/keyorix secret create --name "stripe-api-key" --value "sk_test_..." --project 1 --environment 1
./bin/keyorix secret get --id 1 --show-value                              # reveal (audited)
./bin/keyorix secret rotate --id 1 --value "sk_test_...-v2"                # creates version 2
./bin/keyorix secret versions --id 1                                       # read the table, not the "Latest Version" line (see rough edges)
./bin/keyorix secret delete --id 1 --force                                 # soft-delete
./bin/keyorix secret trash --project 1                                    # it's right here
./bin/keyorix secret restore --id 1
./bin/keyorix secret get --id 1 --show-value                               # exact value back
```

## 6. A machine identity reading a secret (~3 min)

```sh
./bin/keyorix machine create --name ci-app --project default --type ci
./bin/keyorix machine grant-role ci-app --project default --role project_viewer
./bin/keyorix machine token issue ci-app --name "ci-pipeline-token" --project default
```

Then, as the "CI job" would:

```sh
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/secrets/1
```

## 7. Audit trail + tamper-evidence (~4 min) — the dramatic finish

```sh
./bin/keyorix audit logs --limit 10        # find the reveal and the machine read
./bin/keyorix audit export --all > audit.ndjson
./bin/keyorix audit verify                 # Audit chain: VALID
```

For the dramatic version (needs the server stopped and `sqlite3` on hand):

```sh
kill %1   # stop the background server
sqlite3 ./keyorix.db "UPDATE audit_events SET description='TAMPERED' WHERE id=5;"
KEYORIX_CONFIG_PATH=./keyorix.yaml ./bin/keyorix-server &
./bin/keyorix audit verify                 # Audit chain: BROKEN, first broken id: 5
```

Then restore the original description and re-verify `VALID` before moving on.

## Known rough edges

Everything below was found and filed driving this exact script (DEMO-1,
2026-10-03). Fixed items are already merged or awaiting merge; the rest are open.

**Blockers worth knowing before you go live:**
- MFA/TOTP enrollment always fails (server rejects a correct, promptly-submitted
  code every time) — [#2552](https://github.com/keyorixhq/keyorix/issues/2552).
  Don't attempt it live.
- A least-privilege, project-scoped user can't use CLI commands that take
  `--project`, even for a project they were explicitly granted — the CLI always
  resolves `--project` via an admin-only endpoint —
  [#2562](https://github.com/keyorixhq/keyorix/issues/2562). Demo step 4 via the
  web UI instead.
- `admin recovery-key rotate` and `admin backup` both refuse to run against a live
  server on both SQLite and Postgres — stop the server (or
  `docker compose stop backend`) first. SELF_HOSTING.md documents running both
  live; that doesn't currently work —
  [#2540](https://github.com/keyorixhq/keyorix/issues/2540) /
  [#2602](https://github.com/keyorixhq/keyorix/issues/2602).
- Restoring a Postgres backup into a genuinely fresh/empty `keyorix_keys` volume
  (the real disaster-recovery scenario) fails —
  [#2604](https://github.com/keyorixhq/keyorix/issues/2604). Not reproduced on
  SQLite restoring into the same config the backup came from.

**Polish, safe to demo through:**
- `keyorix secret versions`' "Latest Version" summary line is wrong (fixed in
  [PR #2566](https://github.com/keyorixhq/keyorix/pull/2566), pending merge) — read
  the table above it instead.
- The CLI's own "Next steps" after bootstrap said `keyorix-next login`, a command
  that doesn't exist (fixed in
  [PR #2490](https://github.com/keyorixhq/keyorix/pull/2490), pending merge).
- `secret delete`'s confirmation prompt said "cannot be undone, permanently
  deleted" — it's actually a restorable soft-delete, exactly as step 5 above shows
  (fixed in [PR #2569](https://github.com/keyorixhq/keyorix/pull/2569), pending
  merge).
- `docker-compose.yml`'s pinned image tags are already behind the latest release —
  [#2601](https://github.com/keyorixhq/keyorix/issues/2601).
- The Projects list page shows a wrong "created X ago" time —
  [#2553](https://github.com/keyorixhq/keyorix/issues/2553).
