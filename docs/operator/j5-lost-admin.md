# Recovering a locked-out admin

What to do when every admin account is locked out, password-lost, or MFA-lost, and you
still have shell access to the host running the server. It assumes the shipped config
(`security.require_mfa: true`, the default) and a server that serves TLS with the certificate
`admin init` generated, so the CLI needs `--ca-file certs/server.crt` (or `keyorix config set
ca_file`).

Output captured on `deb388fb3`, 2026-11-22, native (SQLite, binaries built from that commit, server
on 127.0.0.1). The recovery key, one-time passwords, TOTP secret, recovery codes and the host user
name are replaced by placeholders, and user ids, times and the port differ on your install. The
`admin` commands also print timestamped `storage: opening existing SQLite database ...` log lines on
stderr; they are left out below. The CLI's interactive prompts (`Password:`, `Authenticator code
...`) were **not** captured, because the capture environment had no terminal: the CLI was driven
through `KEYORIX_PASSWORD`, `KEYORIX_MFA_CODE`, `KEYORIX_CURRENT_PASSWORD` and
`KEYORIX_NEW_PASSWORD`, which print only the result lines shown. The SSO, container and Kubernetes
variants are pending the e2e VM.

A user who has only lost their authenticator code, and is not locked out of everything, may not
need this page: see [lost-totp-runbook.md](lost-totp-runbook.md) for the decision tree.

## 0. Before you're locked out: generate a recovery key

Do this once, ahead of time, and store the printed key somewhere offline (a password
manager, a sealed envelope) — **not** in this terminal's scrollback or a log file. It is
shown exactly once.

```bash
export KEYORIX_MASTER_PASSWORD_FILE=./secrets/master_password   # or KEYORIX_MASTER_PASSWORD, --passphrase-file, --passphrase-stdin
keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

To get the key age-encrypted instead of printed, add `--recipient` (and optionally `--output <file>`).
Use a **hybrid post-quantum recipient** (`age1pq1...`, made with `age-keygen -pq`): an
age-encrypted recovery key can be copied and stored today, then opened years later by a quantum
attacker if it was encrypted to a classical key. A classical `age1...` or `ssh-ed25519` recipient
still works, but the command prints a `WARNING` on stderr and carries on. A malformed recipient is
refused before anything changes, so the old key stays valid. Decrypt with `age -d -i <identity file> <output>`
(age 1.3 or newer for hybrid identities).

Expected:

```
Recovery key generated (generation 1).

=====================================================================
  RECORD THIS KEY NOW -- it is shown exactly once and cannot be
  recovered later. Store it offline (password manager, sealed
  envelope) -- NOT in this terminal's scrollback or a log file.

  XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX
=====================================================================

On a local-KEK-file install (storage.encryption.key_provider.type: file or unset), this key does not protect your secrets from host root -- it protects your admin account from anyone who is not you.
```

(`XXXXX-...` stands for the real key: eleven groups, the last one two characters long.) The
final line is the command's own wording. Running this command again
replaces the key; the old one stops working immediately.

**SSO-managed administrators.** If every administrator is provisioned by an identity
provider (SSO or SCIM), an IdP outage or deprovisioning leaves no one who can sign in.
`admin validate --posture` warns about it (louder when no recovery key exists): create a
local break-glass administrator, a password account no IdP manages (`keyorix user create`,
then `keyorix rbac assign-role` with the administrator role), keep its credentials offline,
and generate the recovery key above.

## 1. When locked out: stop the server

`recover-admin` needs exclusive access to the database, the same as any other `admin`
command.

```bash
# stop the running keyorix-server process first
```

## 2. Recover the account

```bash
printf '%s' 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX' | \
  keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

`--user` is the account's **email**, not its username: `--user admin` answers
`Error: recover-admin: no account with email "admin": User not found: user not found` (exit 1).
The first admin created by `keyorix system init` has the email `admin@keyorix.local` unless
`--admin-email` was given.

`--recovery-key` must be exactly `-` — the key is always read from stdin, never a
command-line argument, so it never ends up in shell history or `ps` output.

Expected:

```
Recovered admin account: admin (user id 1).
Reset: account state, password, MFA enrollment,
  0 WebAuthn credential(s), login-lockout state, 1 active session(s).

One-time password (shown once — copy it now, it cannot be retrieved again):
  <one-time password: 20 characters>
Expires: 2026-11-23T01:20:48Z (UTC). After that, login with it is refused like a wrong password; run recover-admin again for a new one.
Log in as "admin" with this password. That session lasts at most 15 minutes and can only set a new
password (keyorix change-password) and enrol a second factor (keyorix mfa enroll + activate), in either
order. When both are done it ends; log in again with the new password and a code.
```

The exit status is 0. The run took the server's presence lock, so with the server still running it
stops with `Error: a Keyorix server (or another admin command) appears to be using this database
... stop it first, or pass --force if you are certain this is safe.` (exit 1) and changes nothing.

This reactivates the account if it was deactivated, sets a one-time password (printed
above, shown exactly once — copy it now), clears MFA/WebAuthn enrollment and the old
recovery codes (forcing re-enrollment), clears any lockout, and revokes every session
belonging to that account. The one-time password **expires**: 24 hours after the run by
default (`security.recovery_one_time_password_ttl`, e.g. `4h`), at the UTC time printed
on the `Expires:` line. Log in and change it before then; an expired password is refused
exactly like a wrong one (same `401`, no hint that it was merely late; the server audits
`auth.one_time_password_expired`, and each refused attempt counts toward the account
lockout). If it expires unused, run `recover-admin` again — it issues a fresh password
and a fresh expiry. It touches nothing else — no other user, role, project, or
secret. Every use is written to the audit trail (`admin.recover_admin`, naming the host
user who ran the command) and notifies every current admin, whether or not the server
happens to be running when you do this.

## 3. Restart the server, then log in with the one-time password

```bash
KEYORIX_CONFIG_PATH=./keyorix.yaml keyorix-server     # the server has no --config flag
keyorix login --server https://127.0.0.1:8081 --ca-file certs/server.crt --username admin   # paste the one-time password at the hidden prompt
```

Expected: `Logged in to https://127.0.0.1:8081 as admin.` This is a **setup session**: it
lasts at most 15 minutes (refreshing does not extend it) and can do exactly two things —
set a new password and enrol a second factor. Everything else is refused:

```
$ keyorix secret list
Error: failed to list secrets: Finish account setup before continuing: change your password and enrol a second factor (MFA), in either order. (HTTP 403) Next step: set your own password with `keyorix change-password`; if the message above also asks for a second factor, enrol it with `keyorix mfa enroll`, then `keyorix mfa activate`.
```

(The command exits 4. Older builds printed the CLI's generic 403 hint here, "you do not have
permission for this ...", which did not apply; what is owed is in the message before the hint.)

Over the API the refusal names what is still owed:
`{"error":"PasswordChangeRequired", ..., "pending_steps":["change_password","enroll_mfa"]}`.
If the 15 minutes run out, log in again with the same one-time password — as long as it
has not expired (step 2 printed when); once it has, go back to step 2.

## 4. Enrol a second factor and set a real password (either order)

Enrol TOTP (or, in the web UI, a passkey). The password `mfa activate` asks for is the
one-time password until you have changed it:

```bash
keyorix mfa enroll        # scan the otpauth:// URI or type the base32 secret into your app
keyorix mfa activate      # prompts for a code from the app and the account password
```

Expected, from `mfa activate`:

```
MFA enabled. This session stays signed in; other sessions were signed out, and your next "keyorix login" asks for a code.

Save these recovery codes now -- they will not be shown again:

  XXXXX-XXXXX
  ... (ten codes in all)
```

Save them now, they are shown once. The session stays signed in because the password change is
still owed.

```bash
keyorix change-password   # prompts for the current (one-time) password and the new one
```

Expected:

```
Password changed. Account setup is complete and this session has ended:
run "keyorix login" with the new password and a code from your authenticator app.
```

Changing the password first and enrolling second works the same way; whichever step is
last ends the session (`mfa activate` then says `Account setup is complete ...`). Both
commands prompt without terminal echo. Passwords and codes are never accepted as flags (argv is
visible to other users): in a script set `KEYORIX_CURRENT_PASSWORD` and `KEYORIX_NEW_PASSWORD`
(or the `_FILE` forms) for `change-password`, and `KEYORIX_MFA_CODE` for `mfa activate`.

## 5. Log in normally, with the second factor

```
$ keyorix secret list
Error: failed to list secrets: Invalid or expired token (HTTP 401) Next step: run `keyorix login` to sign in again (the session may have expired or been revoked).
$ keyorix login --server https://127.0.0.1:8081 --ca-file certs/server.crt --username admin
Logged in to https://127.0.0.1:8081 as admin.
$ keyorix secret list
Secrets List
============
Project: all, Environment: all
Total: 0, Showing: 0 (offset: 0, limit: 50)

No secrets found.
```

(The `keyorix secret list` before the login exits 3. At a terminal, `keyorix login` prompts for `Password:` (the new
password, no echo) and `Authenticator code (or an unused recovery code):`; those prompts were not
captured. Without a terminal there is nothing to prompt on, and `keyorix login` stops with an error naming the flag to use for the code; prefer a terminal for a recovery.) The one-time password no
longer works (`401`). A code that was just used (for example by `mfa activate` in the same 30-second
window) is refused: `Error: second-factor verification failed: Invalid or expired code (HTTP 401)`,
and the audit trail records each refusal as `mfa.failed`. Wait for the next code. The audit trail
shows the whole recovery (`keyorix audit logs --limit 12`; the two `mfa.failed` rows are such refused
codes, and `auth.login` rows appear once per login):

```
ID     TIME (UTC)           ACTOR            KIND      EVENT                            DESCRIPTION
40     2026-11-22 01:21:34  admin            user      auth.login                       User admin logged in
39     2026-11-22 01:21:34  admin            user      mfa.login_verified               user admin passed MFA
38     2026-11-22 01:21:19  admin            user      mfa.failed                       failed MFA login for user 1
37     2026-11-22 01:21:16  admin            user      mfa.failed                       failed MFA login for user 1
36     2026-11-22 01:21:12  admin            user      auth.account_setup_completed     user 1 finished account setup in a setup-only session (both setup steps are done); every session was revoked and the next login requires the second factor
35     2026-11-22 01:21:12  admin            user      auth.password_changed            user 1 changed their own password
34     2026-11-22 01:21:00  admin            user      mfa.activated                    user admin activated MFA
33     2026-11-22 01:21:00  admin            user      mfa.reauth_verified              user admin completed MFA re-authentication (phase: activate_reauth)
32     2026-11-22 01:21:00  admin            user      mfa.enrolled                     user admin began MFA enrolment
31     2026-11-22 01:20:57  admin            user      auth.login                       User admin logged in
30     2026-11-22 01:20:53  system           system    license.evaluated                License evaluated at startup: none — no license installed — running the community baseline
29     2026-11-22 01:20:53  system           system    data_retention.policy_configured Data retention policy applied: anomaly_alerts=0d ...
```

and, one page further back (`--cursor` from the "Next page" line), the `admin.recover_admin` event
with the host user who ran step 2 (the host user name is replaced here):

```
28     2026-11-22 01:20:48  admin            admin_cli admin.recover_admin                      keyorix-server admin recover-admin, run by host user "<host user>" (uid 501), restored account "admin" (user id 1): reactivated, password reset required, MFA cleared, 0 WebAuthn credential(s) cleared, login-lockout cleared, 1 session(s) revoked (recovery key generation 1); one-time password expires 2026-11-23T01:20:48Z
```

(`keyorix audit logs` prints the audit rows newest first; the server's start writes the
`license.evaluated` and `data_retention.policy_configured` rows between the recovery and the login.)

**Not locked out yourself?** `recover-admin` is for the *last* way back into your own account.
If it is a colleague whose one-time password expired or got lost and you can still log in, you
do not need the host or the recovery key: any administrator with `users.write` (and rank over
that account) can run `keyorix user reissue-one-time-password <user id or email>`. It prints a
new one-time password once, ends the user's sessions and puts them through the same
change-password / enrol-MFA setup session described here. It refuses your *own* account (that
is what this runbook is for) and SSO-only users. See
[CONFIGURATION.md](../CONFIGURATION.md#security) ("Reissuing a one-time password").

```
$ keyorix user reissue-one-time-password alice@example.com
Reissuing one-time password for user 2 (alice@example.com)...
One-time password for alice@example.com (relay securely — it is shown only once and must be changed on first login; the user's existing sessions have ended):
  <one-time password: 20 characters>
Expires: 2026-11-25T01:21:44Z (UTC). After that, login with it is refused like a wrong password; reissue another with `keyorix user reissue-one-time-password`.
$ keyorix user reissue-one-time-password admin@example.com        # your own account
Reissuing one-time password for user 1 (admin@example.com)...
Error: reissue one-time password for user 1 (admin@example.com) failed: Cannot reissue your own one-time password; use `keyorix-server admin recover-admin` to recover your own account (HTTP 400)
```

(The refusal exits 1. The reissued password expires after 72 hours by default, not the 24 hours of
`recover-admin`.)

Do **not** set `security.require_mfa: false` to get through this: it is not needed, and it
weakens every account on the install. The same setup session is what a one-time-password
user (`keyorix user create --one-time-password`, which also prints an `Expires:` time,
72 hours by default, `security.one_time_password_ttl`), a user an admin forced to reset
(`keyorix user force-password-reset`) or a user whose password expired gets on a
`require_mfa` install when they have no second factor yet. With `require_mfa: false` the
one-time-password login is only confined to `change-password`, and the session continues
after it.
