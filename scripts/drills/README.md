# Operational drills

Every drill runs the real `keyorix-server` and `keyorix` binaries (no mocks, no container engine)
in a throw-away directory under `$DRILL_ROOT` (default `.scratch/drills`). Shared helpers are in
`lib.sh`; `load.sh` is a library for the drills that need background traffic.

Backends are chosen with `DRILL_BACKEND=sqlite` (default) or `DRILL_BACKEND=postgres`. PostgreSQL
drills read the URL of an EMPTY database from the file named by `DRILL_PG_DSN_FILE` (and
`DRILL_PG_DSN_FILE2`, `DRILL_PG_DSN_FILE3` where the table says so). A drill needs no `psql`:
without it, `tools/pgsql.go` stands in.

Exit status: 0 = every check passed (or the whole drill had nothing to run and said so),
non-zero = a check failed (`DRILL FAILED: ...` on stderr). A leg that is not covered on the
selected backend prints one line, `SKIP <backend>: <reason>`, and the drill goes on.
`DRILL_BACKEND=postgres` with no `DRILL_PG_DSN_FILE` prints `SKIP postgres: ...` and exits 0.

| Drill | Backends covered | Runtime | What it proves |
| --- | --- | --- | --- |
| `accept-loss.sh` | sqlite, postgres (step 6, the host witness file, is SQLite only: `SKIP postgres`) | a few minutes | A deleted audit row reads BROKEN; `admin audit accept-loss` refuses a wrong id, writes nothing without `--confirm`, then seals the gap (SEALED, never valid); the seal survives `rotate-kek`, an unfinished acceptance is resumed on the new key, a garbled seal record stops the audit key transition |
| `upgrade.sh` | sqlite, postgres | under 2 min | The previous release's data boots under the new binary, startup log matches `docs/UPGRADING.md`, seeded data and logins survive, the audit chain stays VALID and grows |
| `backup-restore.sh` | sqlite, postgres (needs `DRILL_PG_DSN_FILE2`; the tamper leg also `DRILL_PG_DSN_FILE3`, else `SKIP postgres`) | under 2 min | `admin backup` then `admin restore` into a fresh target: restore's own audit check passes, `verify-audit` against an off-host checkpoint anchor is VALID, the server boots on the restored data (logins, secrets, shares, machine token), the post-backup write is absent; a tampered archive, a non-empty target and a stale backup over a newer database are refused |
| `key-rotation.sh` | sqlite, postgres (needs `DRILL_PG_DSN_FILE2`) | several minutes | Offline DEK rotation (dry run, refusal beside a live server, confirm), a rotation killed with SIGKILL leaves readable data, KEK rotation (old passphrase refused, new one works, the pre-rotation backup still restores), and provider migration password, file, password; data and audit chain intact throughout |
| `disaster.sh` `kill9` | sqlite, postgres | a few minutes | SIGKILL under four writers three times: restart needs no `--force`, every acknowledged write survives, the audit chain verifies |
| `disaster.sh` `pgdown` | postgres only (`SKIP sqlite`; needs `DRILL_PG_DSN_FILE2` or `DRILL_PG_DSN_FILE`) | under 2 min | PostgreSQL going away never yields a success read; the server stops itself on the lost presence lock (`INV-STORAGE-session-advisory-lock-loss`) without a panic; restarted against the returned database it serves and accepts writes |
| `disaster.sh` `diskfull` | sqlite only (`SKIP postgres`) | under 2 min | With writes failing like ENOSPC (`ulimit -f`), the server refuses them with a clear log line, keeps what it has and hands out no secret value whose audit row could not be written; after space returns everything works and the chain verifies |
| `rotation-under-load.sh` | sqlite, postgres | under 2 min | `rotate --confirm` beside a live, loaded server is refused without disturbing it; across stop, rotate, start every failed request lies inside the stop-to-healthy window; every acknowledged write reads back, `encryption validate` passes and the chain is VALID |
| `kill9-soak.sh` | sqlite, postgres | several minutes | The server process killed with SIGKILL at random points (every 4th during start-up) under read/write/delete load: each restart needs no operator, `verify-audit` is VALID after every kill, every acknowledged write reads back (`SOAK_SEED` replays a run); the database itself is not killed |
| `selftest.sh` | none (no server; helper functions and a static scan of these scripts) | seconds | `verify_audit`, `totp_fresh` and the SKIP/exit-status contract above behave; no `cmd \| grep -q` under `pipefail` |

`internal/statemap` `TestDrillScripts_BackendSwitchHasPostgresBranch` fails when a drill script
switches on `DRILL_BACKEND` without a Postgres branch or when this table lacks a drill.
