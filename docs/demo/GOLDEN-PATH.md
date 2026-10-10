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

## 0. Before you're on stage (~1 min)

```sh
git clone https://github.com/keyorixhq/keyorix.git && cd keyorix
./scripts/demo/up.sh
```

One command: builds a local air-gapped image with the web UI embedded,
starts it, bootstraps an admin, and seeds a realistic org — 3 projects, 2
groups, a least-privilege user, 2 secrets (one with 2 versions), a machine
identity, and a populated audit trail — through the public API/CLI only.
Prints the URL and every login it just created. Re-running it is a no-op
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

## 2. MFA enrollment, live (~1.5 min)

The admin is already enrolled by `up.sh` (that is why the login above asked
for a code). To show enrolment itself live, log in as **alice**: the server
confines her to the security page (`/profile?tab=security&mfa=required`) until
she enrols — scan the QR/enter the setup key in any TOTP app, enter the
6-digit code and her password, confirm. Log out, log back in — the server now
challenges for the code. (Disabling it again: Security -> Disable; **use a
fresh TOTP code, not the password** — the password-only path is correctly
rejected once MFA is enrolled, and a rejected attempt currently leaves the
dialog stuck, #2738 — close and reopen it if that happens.)

## 3. Least privilege (~1 min)

`alice` is already seeded with `project_viewer` on `backend-api` only. Show
it either way:

```sh
export HOME=./.demo-2-cli-home   # the isolated CLI credential store up.sh used
./bin/keyorix login --server http://localhost:8080 --username alice --password '<from up.sh output>' \
  --mfa-code <6-digit code>                # only once alice has enrolled her own TOTP (step 2);
                                           # until then require_mfa confines her to the enrolment endpoints
./bin/keyorix secret list --project 2     # numeric ID — alice holds no deployment-wide role,
                                           # so a project NAME needs one; the CLI says so
                                           # and tells you the numeric ID to use instead
```

(Fixed since DEMO-1's #2562 — a scoped user can now reach their own project
via the CLI, with a clear error pointing at the numeric-ID workaround when
they use a name instead.) Or just log in as alice in the web UI and show
`backend-api` is the only project she can see.

## 4. An audited secret reveal (~1.5 min)

```sh
./bin/keyorix login --server http://localhost:8080 --username admin --password '<from up.sh output>' \
  --mfa-code <6-digit code from your authenticator app>
./bin/keyorix secret get --id 1 --show-value       # stripe-api-key, already rotated to v2 by up.sh
./bin/keyorix audit logs --limit 3                 # the reveal is right there: secret.read
```

## 5. A machine identity reading a secret (~1 min)

`ci-app` is already seeded with `project_viewer` on `default` and a token
(printed by `up.sh`). As the "CI job" would:

```sh
curl -H "Authorization: Bearer <machine token from up.sh output>" http://localhost:8080/api/v1/secrets/1
./bin/keyorix audit logs --limit 3    # actor_type=machine_identity on the read
```

## 6. Audit search + offline chain verification (~2 min) — the dramatic finish

```sh
./bin/keyorix audit logs --limit 10
./bin/keyorix audit export --all > audit.ndjson
./bin/keyorix audit verify                 # Audit chain: VALID
```

For the dramatic version (needs the container stopped and `sqlite3` on the
host, pointed at the named volume):

```sh
docker stop keyorix-demo
docker run --rm -v keyorix-demo-data:/data alpine sh -c \
  "apk add --no-cache sqlite >/dev/null && sqlite3 /data/keyorix.db \"UPDATE audit_events SET description='TAMPERED' WHERE id=5;\""
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

```sh
docker stop keyorix-demo
docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  -e KEYORIX_MASTER_PASSWORD='<from up.sh — see .demo-2-state>' \
  keyorix-demo:airgap /app/keyorix-server admin backup --output backup.tar.gz --config keyorix.yaml
```

Simulate the disaster — move the live database aside — then restore:

```sh
docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  keyorix-demo:airgap mv keyorix.db keyorix.db.pre-restore

docker run --rm -v keyorix-demo-data:/app/data -w /app/data \
  -e KEYORIX_MASTER_PASSWORD='<same as above>' \
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
- Neither published Docker image (full or `-airgap`) embeds the web UI —
  only the GitHub Release tarballs do. `scripts/demo/up.sh` works around
  this by building its own image locally first —
  [#2752](https://github.com/keyorixhq/keyorix/issues/2752).
- `admin recovery-key rotate`, like every admin command except a live Postgres
  backup, needs the server stopped. That is by design: it holds the exclusive
  admin lock for the whole rotation
  ([#2540](https://github.com/keyorixhq/keyorix/issues/2540)). Stop the server
  (`docker stop keyorix-demo`) first, run it, then start the server again.

**Polish, safe to demo through:** none currently open that affect this
script's own steps.
