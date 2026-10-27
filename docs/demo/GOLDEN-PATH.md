# Keyorix 10-minute demo script

A live, working demo script for the air-gapped edition, built on
`scripts/demo/up.sh`: install offline, MFA login, least privilege, an
audited secret reveal, a CI-style machine identity, audit search with
offline chain verification, live backup/restore, and the footprint numbers.
Verified end to end against a fresh SQLite single-node build of
`origin/main` (DEMO-2, 2026-10-05). "Known rough edges" at the end links
every gap this exact script runs into.

This replaces the previous ~20-minute, manually-bootstrapped version
(DEMO-1, 2026-10-03) — `scripts/demo/up.sh` now does steps 0-1 in one
command, and most of DEMO-1's findings are fixed (MFA, least-privilege CLI
access, live backup, fresh-volume restore). What's left open is smaller and
listed below.

No Docker on the demo machine? "Without Docker: the release-binary golden path"
near the end is the ~20-minute version from the two release binaries, with
PostgreSQL, upgrade and recovery (DEMO-1, 2026-10-27).

## Before you're on stage: run the readiness check (~5 min)

`make demo-check` (or `./scripts/demo/check.sh`) walks this exact script end
to end through the public API/CLI only — health, both logins, least
privilege, create/read/rotate/version-history, ACL, the machine-identity
read, MFA, audit + chain verify, the posture report, that a fresh seed shows
exactly the one deliberate Compliance finding (section 1b), secret-read p50 latency,
and (if Playwright is installed) a real-backend UI walk of login/projects/
secrets/audit — printing one ✅/❌ line per step and a final `DEMO READY` /
`NOT READY: N problems`. Run it with no arguments the morning of a demo: it
brings up its own fresh SQLite instance, checks it, and tears it down. Pass
`--keep` to leave that instance running for the actual demo instead of
bringing up a second one by hand; `--postgres` checks the Postgres backend
instead (it brings up `docker-compose.yml` with the backend **and** the web UI
built from this checkout — see "Which images does what" below); `--ui`/`--offline` force the Playwright walk / the airgap-e2e
offline-guarantee leg on. Anything red here is a demo blocker — fix it (or
pick a different flow) before you're in front of a customer, not during.

### Which images does what

| Path | Backend | Web UI |
| --- | --- | --- |
| `scripts/demo/up.sh` (SQLite) | `keyorix-demo:airgap`, built from this checkout | embedded in that same binary |
| `scripts/demo/check.sh --postgres` | `keyorix-demo:airgap`, built from this checkout | `keyorix-demo-web:local`, built from `web/` of this checkout |
| plain `docker compose up` (release / self-hosting) | pinned `ghcr.io/keyorixhq/keyorix-server:<release>` | pinned `ghcr.io/keyorixhq/keyorix-web:<release>` |

The release pins in `docker-compose.yml` stay on a released pair (guarded by
`deploy/compose_pins_test.go`); the demo check overlays both images with ones
built from the checkout, because a released web UI does not match a `main`
backend (login bounced to `/login?logout_error=1`, #3035).

## 0. Before you're on stage (~1 min)

```sh
git clone https://github.com/keyorixhq/keyorix.git && cd keyorix
./scripts/demo/up.sh
```

One command: builds a local air-gapped image with the web UI embedded,
starts it, bootstraps an admin, and seeds a realistic org — 3 projects, 2
groups, a least-privilege user, a second administrator, 3 secrets (one with 2 versions; backend-api has one in Development and one in Production, so the Secrets tab is never empty), a machine
identity, and a populated audit trail — through the public API/CLI only. It also
seeds a **healthy compliance posture with exactly one deliberate finding** (section
1b): every account has a second factor, every project has a completed access review,
every secret/machine identity is classified, and two of the three secrets are on a
rotation policy.
Prints the URL and every login it just created. It also builds a small
`keyorix-demo-sqlite:local` helper image (alpine + `sqlite3`) once, while it
still has network, for the tamper demo in section 6. Re-running it is a no-op
(idempotent); `./scripts/demo/down.sh` stops it, `--wipe` resets it.

**Multi-factor authentication is on, as in every default install**
(`security.require_mfa`), and the demo keeps it on. `up.sh` therefore enrols
TOTP for the demo admin through the real API (`keyorix mfa enroll` / `mfa
activate`, no database writes) and prints a boxed **"ADD THIS TO YOUR
AUTHENTICATOR APP NOW"** step with the setup key, the `otpauth://` URI, a QR
code when `qrencode` is installed, and the recovery codes. Do that once, on
the phone you will use on stage, before you start. The same details stay in
`.demo-2-state` (re-printed by every re-run) so a lost key is recoverable
while the demo exists.

If any seeding step fails, `up.sh` removes the half-built container and data
volume again and says so; fix the cause and re-run it. A volume left behind
by an older interrupted run is replaced the same way.

Say out loud: this exact container — same image, same binary — runs with
**zero outbound network** the entire time, proven by `scripts/airgap-e2e.sh`
with `--network none`: install, bootstrap, secrets, backup, restore, audit
anchoring, tamper-detection, all offline. No cloud SDKs are linked in at all
(`-tags noaws,noazure,nogcp` — confirmed zero AWS/Azure/GCP packages via
`scripts/airgap-dependency-guard.sh`).

## 1. Log in, show the dashboard (~1 min)

Open the URL `up.sh` printed (default **http://localhost:8080**) and log in
with the admin credentials it printed plus the 6-digit code from your
authenticator app. Walk the dashboard: total secrets,
active users, audit events, security status.

## 1b. The one finding: a production secret with no rotation policy (~1.5 min)

Open **Compliance**. A fresh demo is deliberately calm: the control matrix reads
`16 controls · 12 pass · 1 gap` (the other 3 are optional controls that are not
configured on a demo: certificate scanning, data retention, signed-update keys). The
single gap is **Secret-rotation hygiene**: *0 overdue, 0 due soon; 12 of 13 secrets
covered*. That is the talking point, and it is a real one: `payments-webhook-secret`
in backend-api / Production was added after the rotation policies were written, so
nothing would ever tell anyone it is going stale. Keyorix finds it because it checks
coverage as well as age ("every secret is on a schedule", not just "nothing is
overdue yet").

Fix it live, and watch the matrix go to `0 gaps` after a reload:

```sh
./bin/keyorix rotation create --name backend-api-prod-90d \
  --scope environment --environment-id 6 --interval-days 90
```

Why exactly this finding: it needs no time travel (a fresh install cannot have an
*overdue* secret, only an uncovered one), it fires deterministically, and the fix is
one command. To get the talking point back, re-seed:
`./scripts/demo/down.sh --wipe && ./scripts/demo/up.sh`. `make demo-check` fails
if a fresh demo shows anything other than exactly this one gap.

Anomalies: a fresh demo starts with **no open anomalies**. The detector's first pass
runs 1-5 minutes after the server starts and flags the seed's own first accesses
(creating, rotating and revealing a secret as admin, alice's one read, the CI machine
read) as low-severity *new user* / *new IP* alerts (and *off hours* outside
06:00-22:00 UTC), because a day-zero install has no access baseline yet (a user or IP
must be seen for 24 hours before it counts as "known", so an attacker cannot make
themselves normal). `up.sh` waits for that pass (up to ~5 minutes at the end of the
run) and acknowledges exactly those alerts, so the Alerts tile and the Compliance
page are calm when you open them; they stay in Audit -> Anomaly Alerts as
acknowledged. What you do next is live: log in as alice from a browser and read
`db-password`, and a fresh *new IP* alert appears at the next pass (hourly), which is
a good "the detector is on" moment. `make demo-check` fails if a fresh demo still has
open anomalies 6 minutes after start. See "Known rough edges".

## 2. MFA enrollment, live (~1.5 min)

The admin, alice and the second admin (`security-officer`) are already enrolled by
`up.sh` (that is why the login above asked for a code, and why Compliance shows
100% second-factor coverage); their setup keys are in `.demo-2-state`. To show
enrolment itself live, create a brand-new user and log in as them:

```sh
KEYORIX_INITIAL_PASSWORD='<a long passphrase>' ./bin/keyorix user create \
  --username dana --email dana@keyorix.demo
```

The server confines **dana** to the security page
(`/profile?tab=security&mfa=required`) until she enrols — enter the setup key in
any TOTP app (the dialog shows no QR code yet, #3738: type the 32-character key
into the phone, or use a desktop authenticator), enter the 6-digit code and her
password, confirm. Log
out, log back in — the server now challenges for the code. While she is not yet
enrolled, Compliance's second-factor coverage drops below 100% and that control is
a gap; it returns to 100% the moment she enrols. (Disabling it again: Security -> Disable; **use a
fresh TOTP code, not the password** — the password-only path is correctly
rejected once MFA is enrolled, and a rejected attempt currently leaves the
dialog stuck, #2738 — close and reopen it if that happens.)

## 3. Least privilege (~1 min)

`alice` is already seeded with `project_viewer` on `backend-api` only. Show
it either way:

```sh
export HOME=./.demo-2-cli-home   # the isolated CLI credential store up.sh used
./bin/keyorix login --server http://localhost:8080 --username alice
                                           # paste alice's password (from the up.sh output) at the hidden prompt;
                                           # alice is enrolled by up.sh, so the CLI then prompts for a 6-digit
                                           # code: generate it from her setup key (".demo-2-state", "Alice TOTP key")
./bin/keyorix secret list --project 2     # numeric ID — alice holds no deployment-wide role,
                                           # so a project NAME needs one; the CLI says so
                                           # and tells you the numeric ID to use instead
```

(Fixed since DEMO-1's #2562 — a scoped user can now reach their own project
via the CLI, with a clear error pointing at the numeric-ID workaround when
they use a name instead.) Or just log in as alice in the web UI and show
`backend-api` is the only project she can see.

## 3b. Share, then revoke: a share elevates one secret (~1.5 min)

alice can read `db-password` (secret 2, in `backend-api`) through her
`project_viewer` role, but she cannot change it. A `write` share lets her
update that one secret's value and metadata and rotate it, nothing more: she
still cannot suspend, move or re-share it (#2941, #3001). Revoking the share
takes away exactly that and nothing else. `up.sh` makes the admin `project_admin` on `backend-api`, because
only an owner who is a member of the secret's project can share it (#2976).

```sh
# as admin (alice is user 2)
./bin/keyorix share create --secret-id 2 --recipient-id 2 --permission write
./bin/keyorix share list --secret-id 2          # note the share ID

# as alice (or in the web UI: open db-password, edit the value)
./bin/keyorix secret update --id 2 --interactive   # (type the new value at the hidden prompt) works: the share elevates her on this secret
./bin/keyorix secret suspend --id 2                          # 403: a share never lets her suspend it

# as admin
./bin/keyorix share revoke --share-id <id from share list>

# as alice
./bin/keyorix secret update --id 2 --interactive   # 403 again
./bin/keyorix secret get --id 2 --show-value      # still works: her role's read was never the share's

# as admin
./bin/keyorix audit logs --limit 5   # share_created, share_access_elevated, share_revoked, each naming the share ID
```

If you skip the admin's project role, `share create` is refused with the
reason ("you are not a member of this secret's project"); sharing with
someone who holds no role in `backend-api` is refused the same way ("the
recipient is not a member"). A share never applies to a non-member.

## 4. An audited secret reveal (~1.5 min)

```sh
./bin/keyorix login --server http://localhost:8080 --username admin
# hidden prompts: the admin password (from the up.sh output), then the
# 6-digit code from your authenticator app
./bin/keyorix secret get --id 1 --show-value       # stripe-api-key, already rotated to v2 by up.sh
./bin/keyorix audit logs --limit 3                 # the reveal is right there: secret.read
```

## 5. A machine identity reading a secret (~1 min)

`ci-app` is already seeded with `project_viewer` on `default` and a token
(printed by `up.sh`). As the "CI job" would:

```sh
curl -H "Authorization: Bearer <machine token from up.sh output>" "http://localhost:8080/api/v1/secrets/1?include_value=true"
./bin/keyorix audit logs --actor-type machine_identity --limit 3   # secret.read, actor ci-app, "Machine identity ci-app read secret stripe-api-key"
```

`?include_value=true` is what makes it a value read: that is the call that is
audited as `secret.read` (written before the value is returned). A plain
`GET /api/v1/secrets/1` returns metadata only, no value, and is deliberately
not a `secret.read`, so it leaves no row to show here.

## 6. Audit search + offline chain verification (~2 min) — the dramatic finish

```sh
./bin/keyorix audit logs --limit 10
./bin/keyorix audit export --all > audit.ndjson
./bin/keyorix audit verify                 # Audit chain: VALID
```

For the dramatic version (needs the container stopped; uses the
`keyorix-demo-sqlite:local` helper image `up.sh` built, so there is **no
network access and no `apk add` on stage**):

```sh
docker stop keyorix-demo
docker run --rm --network none -v keyorix-demo-data:/data keyorix-demo-sqlite:local \
  sqlite3 /data/keyorix.db "UPDATE audit_events SET description='TAMPERED' WHERE id=5;"
docker start keyorix-demo
./bin/keyorix audit verify                 # Audit chain: BROKEN, first broken id: 5
```

Then restore the original description the same way and re-verify `VALID`
before moving on — or just `./scripts/demo/down.sh --wipe && ./scripts/demo/up.sh`
for a clean instance if you're not rerunning the tamper demo again this
session.

## 7. Backup and restore (~1.5 min)

This demo's air-gapped edition is SQLite, which has no live-snapshot
primitive — `admin backup` needs the server stopped here, by design (say so
out loud; it's documented, not a bug). Mention, don't demo live (needs a
Postgres backend to show): on Postgres, `admin backup` now works **beside a
running server**, no stop needed — fixed since DEMO-1 (#2602, merged via
#2613).

The demo's master passphrase is a throwaway, DEMO-only value that `up.sh`
writes (mode 0600, gitignored) to `.demo-2-cli-home/demo-secrets.env` as
`KEYORIX_DEMO_MASTER_PASSWORD`; load it into your shell first, never type it:

```sh
. .demo-2-cli-home/demo-secrets.env
docker stop keyorix-demo
docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  -e KEYORIX_MASTER_PASSWORD="$KEYORIX_DEMO_MASTER_PASSWORD" \
  keyorix-demo:airgap /app/keyorix-server admin backup --output backup.tar.gz --config keyorix.yaml
```

Simulate the disaster — move the live database aside — then restore:

```sh
docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  keyorix-demo:airgap mv keyorix.db keyorix.db.pre-restore

docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  -e KEYORIX_MASTER_PASSWORD="$KEYORIX_DEMO_MASTER_PASSWORD" \
  keyorix-demo:airgap /app/keyorix-server admin restore \
  --input backup.tar.gz --config keyorix.yaml --overwrite-existing
# --overwrite-existing: the key files are untouched (same host, same config)
# but still present, so restore needs telling this is a genuine DR restore,
# not an accidental double-restore — it moves them aside, doesn't delete them.

docker start keyorix-demo
./bin/keyorix secret get --id 1 --show-value    # the exact post-rotation value survives
```

Restoring onto a genuinely fresh/empty keys volume on a different host —
the real disaster-recovery scenario `--overwrite-existing` isn't — also now
works, on both backends (was #2604); see `docs/AIRGAP_RUNBOOK.md` for that
full drill rather than live here, since it needs a second volume and isn't
worth the extra live-demo fragility for 10 minutes on stage.

## Optional: emergency access (break-glass) (~1 min)

Break-glass is **off by default** (secure default). `scripts/demo/up.sh` turns it
on explicitly in the demo's `keyorix.yaml` (`break_glass.enabled: true`,
emergency role `project_developer`); on any other install add that block yourself
(see `docs/CONFIGURATION.md#break_glass`) and restart. A user must be a **member
of the project** (a role scoped to it, e.g. `project_viewer`) to activate; it then
lifts them to the emergency role for a limited time.

In the seed, **alice** is `project_viewer` on **backend-api, which is project 2**
(project 1 is `default`, where she has no role, so activating there is refused with
`break-glass is available only to members of the project`). Alice activates; an
administrator (`admin`, or the independent reviewer `security-officer`) lists and
ends it. Each block runs as the user in its first comment line, and `<id>` is the
activation id the first command prints:

```bash
# as alice
keyorix break-glass activate --project-id 2 --justification "prod incident INC-123" --ttl 1h
```

```bash
# as an administrator (admin or security-officer)
keyorix break-glass list --project-id 2
keyorix break-glass revoke --project-id 2 --activation-id <id>
```

`scripts/demo/check.sh` runs exactly these blocks (`scripts/demo/golden-path-breakglass.sh`
extracts them from this section, so the doc cannot drift from what works): the
activation shows as `active` in the list, the revoke ends it, and the audit log
records `break_glass.activated`, `break_glass.revoked`, `role.assigned` and `role.removed`.
Alice can also list her own activations (#3184): `keyorix break-glass list --project-id 2`
run as alice shows only hers; run by an administrator (`roles.read` at the project) it
shows everyone's.

If it is not enabled the command now says so (`break-glass is not enabled on this
server; set break_glass.enabled`) instead of a bare `permission denied`.

**The same path in the web UI** (project → **Break-glass** tab; same server rules,
same audit trail):

1. As the member (e.g. a `project_viewer`): open the project's **Break-glass** tab,
   write the justification (at least 10 characters), pick how long (the server
   shortens anything above its `break_glass.max_ttl`) and press **Request
   emergency access**. The row under *Your activations* turns **Active** and counts
   down to expiry; when it reaches zero it shows **Expired**.
2. As the admin (`roles.read` at the project): the same tab now lists
   *All activations on this project*, with who, when, the justification and the status.
3. With `roles.assign`, press **Revoke** on an active row and confirm in the dialog.
   The row turns **Revoked**; the member's own list shows it revoked too.

If break-glass is off, the tab says "Break-glass is not enabled on this server"; if the
project requires MFA and the session has no second factor, it says so and links to
enrolment. Someone who is not a member of the project sees a refusal, not a list.

## 8. Footprint (~30 sec) — close on the koi-pond pitch

Measured 2026-10-05, one Docker build, arm64, indicative (not a repeated
benchmark — see `~/proj/prompts/reports/SESSION-R.md` for the methodology
this follows):

| | Air-gapped | Full |
|---|---|---|
| Image size (installed) | 146 MB | 196 MB |
| Image size (download, gzip proxy) | ~36 MB | ~46 MB |
| `go list -deps ./server` package count | 688 | 1019 |
| ...of which AWS/Azure/GCP SDK | **0** | 145+ |
| Idle memory (one container, served `/health` once) | ~11.6 MB | — |

Say out loud: this is the same "16 MB idle, serving immediately, zero cloud
SDK" pitch the footprint benchmark already made against Vault/OpenBao/
Infisical (`~/proj/prompts/reports/SESSION-R.md`) — now demonstrated live,
offline, in front of the audience, not just measured in a lab.

## Without Docker: the release-binary golden path (~20 min)

The same story from the two release binaries, the way a customer without Docker
installs it: secure defaults on (TLS, MFA, rate limiting), SQLite or PostgreSQL.
Walked end to end twice by DEMO-1 on 2026-10-27 from `main` @ `112c537a3` (A:
SQLite with the air-gapped server build, B: PostgreSQL), with the upgrade from
v0.96.3 and the break-glass/recovery drill. The DEMO-1 journey PR adds
`TestJourney_ReleaseBinaryGoldenPath` (`scripts/e2e/journeys/`), which runs steps
1-8 against real binaries so the sequence cannot silently break. Times are what each
step took live.

Run everything from an empty install directory. Use `keyorix-server-airgap_linux_*`
as `bin/keyorix-server` on an air-gapped host: nothing below needs the network.
Without a phone to hand, any RFC 6238 TOTP generator fed the setup key works.

### 1. Install and first start (~3 min)

```sh
mkdir -m 700 ~/keyorix && cd ~/keyorix && mkdir -m 700 bin
# bin/keyorix-server and bin/keyorix: the release assets (QUICK_START.md "Get the binaries")
./bin/keyorix-server admin generate-secrets          # master passphrase, bootstrap token, admin password: 0600 files, never printed
./bin/keyorix-server admin init --config ./keyorix.yaml        # secure baseline + self-signed TLS cert
#   PostgreSQL instead: admin init --storage-type postgres, set storage.database.dsn,
#   put the DB password in secrets/db_password and export KEYORIX_DB_PASSWORD_FILE for every command
export KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password
./bin/keyorix-server admin encryption init --config ./keyorix.yaml
./bin/keyorix-server admin migrate --config ./keyorix.yaml
./bin/keyorix-server admin validate --posture --config ./keyorix.yaml    # "No deviations found."
./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml \
  --recipient ~/.ssh/id_ed25519.pub --output ./recovery-key.age         # encrypted to you, never printed
KEYORIX_CONFIG_PATH=./keyorix.yaml KEYORIX_BOOTSTRAP_TOKEN_FILE=secrets/bootstrap_token ./bin/keyorix-server &
curl --cacert certs/server.crt https://localhost:8080/health              # "status":"healthy"
```

Say out loud: TLS from the first start (plain `http://` is refused), `/metrics`
behind a token, a recovery key that only you can open.

### 2. First admin and MFA (~2 min)

```sh
./bin/keyorix config set ca_file "$PWD/certs/server.crt"
KEYORIX_ADMIN_PASSWORD_FILE=secrets/admin_password KEYORIX_BOOTSTRAP_TOKEN_FILE=secrets/bootstrap_token \
  ./bin/keyorix system init --server https://localhost:8080 --admin-username admin --admin-email admin@acme.example
./bin/keyorix login --server https://localhost:8080 --username admin < secrets/admin_password
./bin/keyorix secret list        # refused: "This deployment requires multi-factor authentication"
./bin/keyorix mfa enroll         # setup key + otpauth:// link
./bin/keyorix mfa activate       # code, then password; prints 10 recovery codes once
```

Secrets stay locked until the admin has a second factor: that is the default.
The next `login` asks for a code. Each code works once, so wait for the next one
after activating.

### 3. Teams and projects (~2 min)

```sh
./bin/keyorix project create --name payments          # id 2, environments 4/5/6
./bin/keyorix project create --name storefront        # id 3, environments 7/8/9
./bin/keyorix project create --name data-platform
./bin/keyorix group create --name team-payments
./bin/keyorix group create --name team-storefront
```

In the web UI (Projects → New Project) a project is one dialog; it opens on the
new project's Production secrets.

### 4. People and least privilege (~3 min)

```sh
KEYORIX_INITIAL_PASSWORD_FILE=bob.pw   ./bin/keyorix user create --username bob   --email bob@acme.example
KEYORIX_INITIAL_PASSWORD_FILE=carol.pw ./bin/keyorix user create --username carol --email carol@acme.example
./bin/keyorix group add-member team-payments --user bob
./bin/keyorix group add-member team-storefront --user carol
./bin/keyorix rbac assign-role-to-group --group team-payments   --role project_developer --project payments
./bin/keyorix rbac assign-role-to-group --group team-storefront --role project_viewer    --project storefront
./bin/keyorix rbac assign-role --user admin@acme.example --role project_admin --project payments
```

Log in as carol in the web UI: she is confined to enrolling MFA (Profile →
Security → Enable, setup key + code + password), then sees only `storefront`.
From the CLI as carol: `secret get` on a payments secret is `Insufficient
permissions`, and so are `audit logs`, `user list` and writing her own project's
secret. bob can write payments secrets and cannot read storefront.

### 5. Secrets: create, version, reveal, rotate, delete, restore (~3 min)

```sh
printf %s 'sk_live_v1' | ./bin/keyorix secret create --name stripe-api-key --project 2 --environment 6 --from-file -
printf %s 'sk_live_v2' | ./bin/keyorix secret update --id 1 --from-file -      # version 2
./bin/keyorix secret rotate --id 1                                              # hidden prompt: version 3
./bin/keyorix secret versions --id 1                                            # 3 versions
./bin/keyorix secret get --id 1 --show-value                                    # the reveal (audited)
./bin/keyorix secret delete --id 1      # type the name, then "yes": soft-delete, prints the restore deadline
./bin/keyorix secret restore --id 1
```

Values never go on the command line: a hidden prompt, a relative file, or stdin
(`--from-file -`).

### 6. A machine identity, the way CI reads (~2 min)

```sh
./bin/keyorix machine create --name payments-ci --project payments --type ci
./bin/keyorix machine grant-role payments-ci --project payments --role project_viewer
./bin/keyorix machine token issue payments-ci --name ci --project payments \
  --expires-in-days 30 --output-file ci.token            # 0600 file, never printed

# in the CI job: no login, just the token
export KEYORIX_SERVER=https://localhost:8080 KEYORIX_TOKEN_FILE=$PWD/ci.token KEYORIX_CA_FILE=$PWD/certs/server.crt
keyorix secret get --ref payments/production/stripe-api-key --show-value
keyorix run --project payments --env production --var STRIPE_KEY=stripe-api-key -- ./deploy.sh
curl --cacert certs/server.crt -H "Authorization: Bearer $(cat ci.token)" \
  "https://localhost:8080/api/v1/secrets/1?include_value=true"
keyorix secret get --id 3 --show-value      # storefront: Insufficient permissions
```

### 7. Audit: find it, export it, prove it (~3 min)

```sh
./bin/keyorix audit search --action secret.read --actor admin          # the reveal
./bin/keyorix audit logs --actor-type machine_identity --limit 5        # the CI reads, and the refused one
./bin/keyorix audit search --action secret.read --actor carol           # "was refused a secret value read"
./bin/keyorix audit export --all > audit.ndjson
./bin/keyorix audit verify                                              # Audit chain: VALID
```

Tamper evidence without stopping anything, on a copy (SQLite):

```sh
sqlite3 keyorix.db ".backup audit-copy.db"
./bin/keyorix-server admin verify-audit --db audit-copy.db      # Verdict: VALID
sqlite3 audit-copy.db "UPDATE audit_events SET description='TAMPERED' WHERE id=47;"
./bin/keyorix-server admin verify-audit --db audit-copy.db      # Verdict: BROKEN, first broken id: 47
```

(`verify-audit` also takes `--pg-dsn` for a PostgreSQL copy; DEMO-1 walked the
tamper step on SQLite only.)

### 8. Backup, wipe, restore (~3 min)

```sh
# PostgreSQL: beside the running server. SQLite: stop the server first.
./bin/keyorix-server admin backup --output ../keyorix-backup.tar.gz --config ./keyorix.yaml
```

The disaster: a new, empty host directory (and, on PostgreSQL, an empty database)
holding only `bin/`, `keyorix.yaml`, `certs/`, `secrets/master_password`,
`secrets/metrics_token` (and `secrets/db_password`):

```sh
./bin/keyorix-server admin restore --input ../keyorix-backup.tar.gz --config ./keyorix.yaml
#   ... verify-audit on the restored database: VALID
```

Start it, log in with the same password and authenticator: the secret reads back
at version 3, the CI read is still in the audit log, `audit verify` is `VALID`.

### 9. Upgrade with data in place (mention, or show from a prepared v0.96.3 install)

Stop the old server, `admin backup` with the **old** binary, replace both binaries,
start. Then `keyorix audit verify --full` (a plain `verify` says `NOT PROVEN` until
then) and delete the two deprecated keys the old config carries: see
[UPGRADING.md](../UPGRADING.md#any-v096x-install-moving-to-the-next-release-two-things-you-will-see).

### 10. Recovery and break-glass (~2 min)

Locked-out admin (lost phone), on the host with the server stopped:

```sh
age -d -i ~/.ssh/id_ed25519 recovery-key.age | \
  ./bin/keyorix-server admin recover-admin --user admin@acme.example --recovery-key -
```

(DEMO-1 fed the key from a plaintext `recovery-key rotate` on stdin; the `age -d`
pipe is the same input, decrypted with the key step 1 encrypted it to.)

It prints a one-time password valid for 24 hours. That login can only change the
password and enrol MFA (the CLI says so). Every use is in the audit log, naming
the host user who ran it. Break-glass (off by default; enable it in
`keyorix.yaml` and restart) is the "Optional: emergency access" section above, run
exactly as written.

## Known rough edges

**Fixed since DEMO-1** (no longer blockers): MFA enrollment/login (#2552),
least-privilege CLI access (#2562), live Postgres backup (#2602),
fresh-volume restore (#2604), stale `keyorix-next` CLI text (#2489), missing
TLS docs (#2491), wrong "Latest Version" summary (#2563), wrong
soft-delete confirmation text (#2568), stale docker-compose image pins
(#2601), wrong relative time on Projects list (#2553).

**New, found while re-walking (DEMO-2, 2026-10-05):**
- The "Disable two-factor authentication" dialog hangs forever (no error
  shown) after one rejected attempt (e.g. password instead of a code), and
  survives closing/reopening — only a full page reload clears it —
  [#2738](https://github.com/keyorixhq/keyorix/issues/2738).
- Fixed since: the published images embed the web UI as of v0.96.0
  (`ghcr.io/keyorixhq/keyorix-server:0.96.0-airgap` serves it; `check.sh`'s
  "web UI served" step is green on it) —
  [#2752](https://github.com/keyorixhq/keyorix/issues/2752). `scripts/demo/up.sh`
  still builds its own image from the checkout, so the demo always matches the
  code you are about to show.
- `admin recovery-key rotate`, like every admin command except a live Postgres
  backup, needs the server stopped. That is by design: it holds the exclusive
  admin lock for the whole rotation
  ([#2540](https://github.com/keyorixhq/keyorix/issues/2540)). Stop the server
  (`docker stop keyorix-demo`) first, run it, then start the server again.
- `admin recovery-key rotate` still refuses to run against a live server
  (SQLite and Postgres) — [#2540](https://github.com/keyorixhq/keyorix/issues/2540)
  was closed 2026-10-04 but the failure still reproduces on current `main`;
  flagged on the issue for the coordinator to confirm. Stop the server (or
  `docker stop keyorix-demo`) first if you want to demo it live.

**Open anomalies on a day-zero install (found DEMO-SEED-1, 2026-10-12; handled by
DEMO-FIX-12, #3152):** the first detection pass, 1-5 minutes after the server starts,
flags the seed's own accesses as *new user* / *new IP* (low) and, between 22:00 and
06:00 UTC, *off hours* (medium). This is the detector working as designed on an
install with no baseline (the baseline-quarantine rule, #101), so the thresholds were
not changed. `up.sh` now waits for that first pass and acknowledges only alerts of
those three types, low/medium severity, whose accessor is a seeded demo principal
(`scripts/demo/lib.sh` `demo_settle_anomalies`); anything else the pass reports stays
open and fails `check.sh`. Whether the creator's own first access to a brand-new
secret should count as "new" remains a product question, not a demo one.

**Found re-walking from the release binaries (DEMO-1, 2026-10-27; all
`demo-polish`, none blocks the demo):**
- `keyorix logout` forgets `ca_file`, so switching users on stage needs
  `keyorix config set ca_file ...` again before the next `login`:
  [#3735](https://github.com/keyorixhq/keyorix/issues/3735).
- `audit search --actor payments-ci` finds nothing: filter machine reads with
  `audit logs --actor-type machine_identity` (as the script does):
  [#3736](https://github.com/keyorixhq/keyorix/issues/3736).
- `secret restore` on a secret that is not deleted says "Storage operation failed:
  Secret not found": [#3737](https://github.com/keyorixhq/keyorix/issues/3737).
- The web TOTP dialog has no QR code:
  [#3738](https://github.com/keyorixhq/keyorix/issues/3738).
- A `project_viewer` sees New Project / edit / delete on Projects (the server
  refuses them): [#3739](https://github.com/keyorixhq/keyorix/issues/3739). Do not
  click them in the least-privilege part.
- A fresh dashboard shows "Inactive users: 1 — no login in 30 days" for users who
  have not logged in yet: [#3740](https://github.com/keyorixhq/keyorix/issues/3740).
- `break-glass list` shows the user as a number:
  [#3741](https://github.com/keyorixhq/keyorix/issues/3741).
- A missing key directory is reported as "a live server ... is using this key
  directory": [#3742](https://github.com/keyorixhq/keyorix/issues/3742).
- Right after an upgrade, `audit verify` says `NOT PROVEN` until
  `audit verify --full`; the v0.96 config carries two deprecated keys:
  [#3743](https://github.com/keyorixhq/keyorix/issues/3743) (documented in UPGRADING.md).
- Copy: the wrong "request access" hint after `recover-admin` and the help of
  `user create`/`logout` are fixed in the DEMO-1 PR; internal references
  ("pre-#1452", "design §3.4") in `verify-audit`/`restore` output remain:
  [#3744](https://github.com/keyorixhq/keyorix/issues/3744).
- With the default TLS (self-signed certificate), a browser shows a certificate
  warning until the presenter trusts `certs/server.crt` (macOS: open it in Keychain
  Access and set it to "Always Trust"), so do that before the demo. The
  `admin init --dev` config (no TLS) avoids it but is DEV-ONLY.
