# Recovering a locked-out admin

What to do when every admin account is locked out, password-lost, or MFA-lost, and you
still have shell access to the host running the server. Every command below was run for
real against a fresh SQLite install while writing this page.

> **Known gap (tracked, not yet fixed):** the last step below — logging back in — does
> not currently work. `recover-admin` clears the account's password with nothing to
> replace it, and the login endpoint has no path for an account with no password set.
> This page documents the parts that DO work today and stops at the point where recovery
> currently dead-ends, rather than claim a working flow that isn't there yet. See the UX
> track's report (`reports/UX.md`, "J5" section) for the root cause and proposed fix.

## 0. Before you're locked out: generate a recovery key

Do this once, ahead of time, and store the printed key somewhere offline (a password
manager, a sealed envelope) — **not** in this terminal's scrollback or a log file. It is
shown exactly once.

```bash
export KEYORIX_MASTER_PASSWORD='your-existing-passphrase'
keyorix-server admin recovery-key rotate --config ./keyorix.yaml
```

Expected:

```
Recovery key generated (generation 1).

=====================================================================
  RECORD THIS KEY NOW -- it is shown exactly once and cannot be
  recovered later. Store it offline (password manager, sealed
  envelope) -- NOT in this terminal's scrollback or a log file.

  3LPS9-HWETE-XULZS-SDNYS-XQ5K9-VDY89-3YVQ8-SU8AP-EP7JG-PJFWU-FH
=====================================================================
```

On a local-KEK-file install, this key does not protect your secrets from host root — it
protects your admin account from anyone who is not you. Running this command again
replaces the key; the old one stops working immediately.

## 1. When locked out: stop the server

`recover-admin` needs exclusive access to the database, the same as any other `admin`
command.

```bash
# stop the running keyorix-server process first
```

## 2. Recover the account

```bash
printf '%s' '3LPS9-HWETE-XULZS-SDNYS-XQ5K9-VDY89-3YVQ8-SU8AP-EP7JG-PJFWU-FH' | \
  keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

`--recovery-key` must be exactly `-` — the key is always read from stdin, never a
command-line argument, so it never ends up in shell history or `ps` output.

Expected:

```
Recovered admin account: admin (user id 1).
Reset: account state, password (reset required on next login), MFA enrollment,
  0 WebAuthn credential(s), login-lockout state, 1 active session(s).
```

This reactivates the account if it was deactivated, clears its password (forcing a reset),
clears MFA/WebAuthn enrollment (forcing re-enrollment), clears any lockout, and revokes
every session belonging to that account. It touches nothing else — no other user, role,
project, or secret. Every use is written to the audit trail and notifies every current
admin, whether or not the server happens to be running when you do this.

## 3. Restart the server, then — this is the gap

```bash
keyorix-server --config ./keyorix.yaml
keyorix login --server http://localhost:8080 --username admin --password 'anything'
```

Today this always returns `401 Unauthorized`, for any password, because step 2 cleared
the password hash and nothing sets a new one. There is currently no host-only way to
finish the recovery — the web login page's "Forgot password?" is a different, email-based
flow, not configured by default, and not part of this mechanism. If you hit this, you'll
need a build with the fix from the tracked issue above, or to set the account's password
directly via a database-level workaround (not covered here, since that isn't a documented
or supported path).
