# Tabletop 2: three Keyorix-side drills (leaked admin token, audit-chain break, lost KEK)

**Status: script ready, not yet run with the team.** Facilitator: Andrei. Plan under test:
[`incident-response-plan.md`](incident-response-plan.md) sections 4, 6, 8.1 and 8.2.
[`tabletop-1.md`](tabletop-1.md) covers the publisher-side case (a bad image); this one
covers an incident **inside a Keyorix deployment**. Use a **throwaway instance**, never a
real one: the steps write audit events, and the audit-chain drill edits a *copy*.

**Commands verified** on 2026-11-28 against binaries built from `origin/main` (`476a87938`),
native SQLite install, self-signed TLS. Every command below was run and the "Expect" column
is what it printed, except those marked † (flags checked against `--help` only, not run) and
the supervisor command in B1. Paths are examples.
Secrets come from `0600` files (`KEYORIX_MASTER_PASSWORD_FILE`, `KEYORIX_PASSWORD_FILE`
and the like), never from a command line. `keyorix` is the CLI (talks to the server);
`keyorix-server admin` runs on the host with the server **stopped** (SQLite).

**Setup (once):** `keyorix-server admin generate-secrets`, `admin init`, `admin encryption init`,
`admin migrate`, `admin recovery-key rotate`, start the server, `keyorix system init`,
`keyorix login`, `keyorix mfa enroll` + `activate` (see
[`quickstart-60s.md`](../operations/quickstart-60s.md)). Then keep one backup:
`keyorix-server admin backup --output backup-1.kxb` (server stopped).

Rules as in tabletop 1: answer from what you could really do on the day; the scribe records
gaps. Per step, the team first says what it would do, then the facilitator shows the command.

## Scenario A: a leaked admin token (SEV2, SEV1 if secrets were read)

A personal access token (PAT) of an admin was pasted into a public place two days ago.

| # | Decision / step | Command | Expect |
|---|---|---|---|
| A1 | Declare, name IC and scribe, write the awareness time (plan 4, T+0) | none | record created |
| A2 | Snapshot before revoking: the audit trail as NDJSON, then hash it | `keyorix audit export --all > inc-audit.ndjson` then `shasum -a 256 inc-audit.ndjson` | `exported N event(s); caught up`, hash in the record |
| A3 | What did the token do? | `keyorix audit logs --user-id <admin id> --limit 100` (add `--since <leak time>`†) | rows such as `pat.created`, `auth.login`, `secret.read` |
| A4 | Find the token | `keyorix pat list` | ID, prefix, scope, `LAST USED`, `REVOKED` |
| A5 | Revoke it | `keyorix pat revoke <id>` | `Token <id> revoked.` Using it afterwards returns HTTP 401 |
| A6 | The admin's own **session** may have leaked too. `user revoke-sessions` refuses your own account (`Cannot revoke your own sessions (HTTP 400)`), so the admin changes the password: | `keyorix change-password` (non-interactive: `KEYORIX_CURRENT_PASSWORD_FILE`, `KEYORIX_NEW_PASSWORD_FILE`) | `Every other active session for this account has been revoked`; the leaked session token then returns HTTP 401 |
| A7 | Another user's sessions | `keyorix user revoke-sessions --id <id>` | sessions end; the user can log in again. Use `user suspend`† to block login |
| A8 | Decide: were secrets read in the window? If yes, section 8.1 of the plan applies: rotate the secrets at their source | `keyorix audit logs --event-type secret.read --since <leak time>`† | list of reads |
| A9 | Is the evidence intact? | `keyorix audit verify` | `Audit chain: VALID` (exit non-zero otherwise) |

**Expected decisions:** revoke before investigating, but only after A2; treat every secret the
token could read as exposed until A8 says otherwise; the sole admin changes the password to
end their own leaked session; the two-person rule is not needed for a revoke, it is for the
advisory and any notice.

## Scenario B: the audit chain does not verify (plan 8.2)

`keyorix audit verify` or the nightly `verify-audit` reports BROKEN. For the drill the
facilitator breaks a **copy**: after step B2, run
`sqlite3 evidence/keyorix.db "UPDATE audit_events SET description='edited' WHERE id=18"`.

| # | Decision / step | Command | Expect |
|---|---|---|---|
| B1 | Do not repair, do not re-baseline. Stop the server | `systemctl stop keyorix` (or your supervisor) | server down |
| B2 | Copy the database with its `-wal` and `-shm` (SQLite) or `pg_dump` (PostgreSQL) | `cp keyorix.db* evidence/` | copy in an evidence directory |
| B3 | Verdict from the copy, no lock, nothing written | `keyorix-server admin verify-audit --json --db evidence/keyorix.db` (`echo $?`) | untouched copy: `Verdict: VALID`, exit 0. After the edit: `Verdict: BROKEN`, `first broken id: 18`, exit 1 |
| B4 | Keep an independent anchor and key off the host | `keyorix-server admin audit export-checkpoint --output evidence/anchor.json`; `keyorix-server admin audit export-checkpoint-key --output evidence/checkpoint.key` | both files written (the key is a shared secret: store it away from the database) |
| B5 | Re-verify with them | `keyorix-server admin verify-audit --db evidence/keyorix.db --checkpoint-key-file evidence/checkpoint.key --anchor evidence/anchor.json` | still BROKEN at id 18, `Anchor source: flag` |
| B6 | Classify: restore, upgrade, migration or manual SQL near row 18? A modified row cannot be re-sealed: | `keyorix-server admin audit accept-loss --first-broken-id 18 --operator <name> --reason "<ticket>" --evidence-sha256 <hash>` | refused: `that is a modified row, not a lost one`. Nothing is written without `--confirm` |
| B7 | The ways forward are in [`audit-chain-break-runbook.md`](../operator/audit-chain-break-runbook.md) sections 7 and 8 (restore a known-good archive, or keep running on the broken chain) | `keyorix-server admin restore --input <archive> --overwrite-existing --replace-existing-data` (`--allow-rollback` if it refuses an archive behind the host) | see the runbook; the restore runs `verify-audit` itself |

**Expected decisions:** SEV2 (SEV1 if secret reads hide in the unverifiable range); copy first;
the verdict is read from the copy; the team knows `accept-loss` is for lost rows only; ask
early whether an off-box anchor exists.

## Scenario C: the KEK is lost (plan 8.1, the other direction)

Two cases, because the answers differ. Case 1: the master passphrase file is gone. Case 2:
the passphrase is known but the `keys/` directory (wrapped DEK and salt) is gone.

| # | Decision / step | Command | Expect |
|---|---|---|---|
| C1 | What exactly is missing? | `keyorix-server admin diagnose` | case 1 with no file: `[FAIL] config parse: ... cannot open secret file`; a wrong passphrase: `[FAIL] KEK/passphrase access ... wrong passphrase or corrupted key file`; case 2: `[FAIL] KEK/passphrase access: key file .../keys/dek.key does not exist` |
| C2 | Case 1: look for the offline copy of the passphrase (the `generate-secrets` output says to keep one away from `keys/` and the database). Found: put it back at the path `KEYORIX_MASTER_PASSWORD_FILE` names | `keyorix-server admin diagnose` | `All startup checks that can fail this server's boot passed.` |
| C3 | Case 1, no copy anywhere: there is **no recovery path in the product**. The DEK is wrapped by a key derived from the passphrase, so every stored secret stays unreadable, backups included (the archive manifest is also checked with a passphrase-derived key). Decide: rebuild and re-enter secrets at their sources | none | the team says so aloud; this is a finding if nobody knew |
| C4 | Case 2: do **not** run `admin encryption init` (it makes new keys, and the old data stays unreadable). Restore the archive that holds the key files | `keyorix-server admin restore --input backup-1.kxb --overwrite-existing --replace-existing-data` | refused if the archive is behind the host's audit trail: `... BEHIND this host's own last known state`. For a real disaster restore add `--allow-rollback`; it records the override |
| C5 | Confirm | `keyorix-server admin diagnose`, then `keyorix-server admin verify-audit` | all `[ OK ]`; restore itself prints `verify-audit on the restored database: VALID` |
| C6 | If the passphrase **leaked** instead of being lost: rotate it (the old database stays decryptable with the old one, so rotate the DEK as well when the attacker may hold ciphertext) | `keyorix-server admin encryption rotate-kek --confirm --new-passphrase-file <file>`, then `keyorix-server admin encryption rotate --confirm`† | `KEK rotation complete.` Copy the new passphrase into the deployment before restart; audit checkpoints now verify with the **new** key (`admin audit export-checkpoint-key`); the old key reads BROKEN by design |

**Expected decisions:** the passphrase backup is the single point of recovery, and who holds
it is written in the contact sheet (plan section 1); a restore costs every write since the
backup; rotating Keyorix's keys does not un-leak secrets an attacker already decrypted
(plan 8.1, step 3).

## Debrief

1. Which command did we have to look up? Is it in the contact sheet or the runbook?
2. A6: could the sole admin have ended their own leaked session faster?
3. B6: did anyone assume a modified row could be sealed?
4. C3: where is the offline passphrase copy, and who can reach it at 02:00?
5. What did the clock say between "first signal" and "evidence copied"?

**Outcome (Andrei fills in after running):** run date ____ ; participants ____ ; gaps ____ ;
plan sections changed ____ ; overall (Pass / Pass with actions / Fail) ____ .
