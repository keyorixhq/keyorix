# Recovering a locked-out admin

What to do when every admin account is locked out, password-lost, or MFA-lost, and you
still have shell access to the host running the server. Every command below was run for
real against a fresh SQLite install while writing this page.

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
Reset: account state, password, MFA enrollment,
  0 WebAuthn credential(s), login-lockout state, 0 active session(s).

One-time password (shown once — copy it now, it cannot be retrieved again):
  _M2vVfCk4K*6%x4v7uKt
Log in as "admin" with this password; you will be required to set a new one immediately.
```

This reactivates the account if it was deactivated, sets a one-time password (printed
above, shown exactly once — copy it now), clears MFA/WebAuthn enrollment (forcing
re-enrollment), clears any lockout, and revokes every session belonging to that account.
It touches nothing else — no other user, role, project, or secret. Every use is written
to the audit trail and notifies every current admin, whether or not the server happens
to be running when you do this.

## 3. Restart the server, then log in with the one-time password

```bash
keyorix-server --config ./keyorix.yaml
keyorix login --server http://localhost:8080 --username admin --password '_M2vVfCk4K*6%x4v7uKt'
```

Expected: `Logged in to http://localhost:8080 as admin.` The account is still
`password_reset_required`, so every OTHER endpoint returns `403` until you actually
change it — confirmed live: `keyorix secret list` right after this login returns
`Error: failed to list secrets: HTTP 403`.

## 4. Set a real password

The thin CLI does not yet wrap `POST /api/v1/auth/change-password` (self-service password
change) as its own command — call it directly with the session token `login` just stored
(`~/.keyorix`/the OS credential store, depending on platform):

```bash
export TOKEN='<the token keyorix login just stored>'
curl -s -X POST http://localhost:8080/api/v1/auth/change-password \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"current_password": "_M2vVfCk4K*6%x4v7uKt", "new_password": "a-real-strong-password-you-choose"}'
```

Expected: `{"data":null,"message":"Password changed","success":true}`. From this point on,
`keyorix secret list` (and everything else) works normally — confirmed live: logging in
again with the OLD one-time password now returns `401` (it was superseded), and logging in
with the new password succeeds with full access restored, no longer confined to the
password-change allowlist.
