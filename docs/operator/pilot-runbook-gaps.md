# Pilot runbook gaps: what works on `main` today

The product gaps the runbooks work (RUNBOOKS-1, #3542) named, re-checked against `origin/main`
(`476a87938`) on 2026-11-28. Each row says **works**, **works with caveat** or **missing**,
and gives the command run or the test that proves it. Runs were native: SQLite, binaries built
from that commit, a throwaway instance, server stopped for the `admin` commands. Nothing was
run on PostgreSQL or in a container (pending e2e VM). The decision log for the gaps that stay
open is [known-limitations.md](known-limitations.md).

| # | Gap named earlier | Status | What proves it | Caveat or what is missing |
|---|---|---|---|---|
| 1 | A non-admin local user with no recovery code has no supported MFA reset | **works** | `keyorix-server admin reset-mfa --user <name> --recovery-key - < <recovery-key file>`: printed `MFA reset for bob`, removed the TOTP factor and 10 recovery codes, revoked 1 session, printed a one-time password. Same command on an admin: `reset-mfa: this account holds a global-admin role: recover it ... with admin recover-admin`. Tests: `TestPerformResetMFA_FullCredentialReset`, `TestPerformResetMFA_Refusals_ChangeNothing` (`server/admin`) | Needs host access, the server stopped (SQLite) and the local recovery key from `admin recovery-key rotate`. SSO, suspended and machine accounts are refused. See [lost-totp-runbook.md](lost-totp-runbook.md) section 4 |
| 2 | Lost admin (password, MFA or lockout) | **works** | `keyorix-server admin recover-admin --user <id or email> --recovery-key - < <file>`: printed `Recovered admin account: admin`, one-time password with a 24 h expiry, login confined to `change-password` and MFA enrolment. Tests: `TestAdminRecoverAdmin_FullFlow_SQLite` (`server`), `TestJourney_RecoverAdminUnderRequireMFA` (`scripts/e2e/journeys`) | Without the recovery key there is no path except the `insecure_keyless_admin_recovery` setting, which the help calls a labs escape hatch. Procedure: [j5-lost-admin.md](j5-lost-admin.md) |
| 3 | Break-glass emergency access | **works with caveat** | Test `TestBreakGlass_ActivateListRevoke` (`server/grpc/services`); activation output captured on 2026-11-22 in [break-glass-runbook.md](break-glass-runbook.md) section 1. `keyorix break-glass --help` lists `activate`, `list`, `revoke`. **Not re-run in this check** | Off by default (`break_glass.enabled`). The degraded-mode and last-resort sections of the runbook were never captured against a failing audit log |
| 4a | Key rotation: DEK | **works** | `keyorix-server admin encryption rotate --confirm`: `Sweep committed: 1 secret_versions ... re-encrypted`, new key version printed | Write-locks the database; take a backup first (item 4b) |
| 4b | Reverse a DEK rotation | **missing** | `keyorix-server admin encryption --help` lists no such command | Only roll forward, or restore the archive taken before the rotation and lose the writes since ([key-rotation-runbook.md](key-rotation-runbook.md) section 6) |
| 4c | Key rotation: KEK (passphrase) | **works** | `keyorix-server admin encryption rotate-kek --confirm --new-passphrase-file <f>`: `KEK rotation complete.`, audit state carried to the new key | The deployment's passphrase must be changed before restart. Effect on backup-manifest signing for archives taken before the rotation: **not tested** |
| 5a | Audit-chain break: detect and take evidence | **works** | `keyorix audit verify` (online); `keyorix-server admin verify-audit --db <copy>`: `VALID` on the copy, `BROKEN`, `first broken id: 18`, exit 1 after an edit to row 18. Test file `internal/auditverify/tamper_exhaustive_test.go` | Online tamper detection depends on a signed checkpoint; a bare re-walk cannot see tail truncation ([audit-chain-break-runbook.md](audit-chain-break-runbook.md)) |
| 5b | Audit-chain break: accept a proven **loss of rows** | **works with caveat** | `keyorix-server admin audit accept-loss --help` (the chain then reads `sealed`, never valid; the sealing run itself was **not run here**, the runbook shows a captured plan in section 7) | Only for lost rows (gap or truncation) |
| 5c | Audit-chain break: restart after a **modified row** | **missing** | `admin audit accept-loss --first-broken-id 18 ...` on a chain with row 18 edited: `that is a modified row, not a lost one` | The break stays in every report and checkpoints stay refused. Ways forward: restore a known-good archive, or keep running on the broken chain |
| 5d | `rotate-kek` makes older audit checkpoints read BROKEN | **works with caveat** | After `rotate-kek`: `verify-audit --checkpoint-key-file <new key>` is `VALID` (`Checkpoint: authenticated ... certifies 28 chained events`); with the **old** key it is `BROKEN` (wrong key) | Export the new key after every rotation; pass earlier keys with `--previous-checkpoint-key-file`. Test: `TestAuditKeyTransition_PurgedInstallStaysValid` (`internal/core`) |
| 5e | `CONFIGURATION.md` calls the checkpoint key DEK-derived | **fixed** | `rg 'KEK-derived' docs/CONFIGURATION.md` (lines 2142, 2187, 2217) | none |

## Filed for the rows marked missing

- 4b, no command reverses a DEK rotation: #4823.
- 5c, no restart after a modified-row break: #4824.
