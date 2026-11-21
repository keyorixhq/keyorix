# Lost TOTP runbook: a user cannot produce a second factor

A user can sign in with a password but not with their authenticator code: a lost phone, a
wiped app, a clock that drifts. This runbook picks the recovery path that exists in the code
today for each kind of account, and says plainly where there is none. For an admin who is
locked out entirely (password, MFA or lockout), the full procedure is
[j5-lost-admin.md](j5-lost-admin.md); this page is the decision tree in front of it.

Do **not** set `security.require_mfa: false` to get someone in. It is not needed for any path
below and it weakens every account on the install.

## 1. Decide which case you are in

| The user | Path |
|---|---|
| Still has an **unused recovery code** | Section 2: it signs the user in and, spent on `mfa/disable`, lets them enrol a new device themselves. Sections 3-4 stay the fallback. |
| Is a **global admin**, no recovery code, you have shell access to the server host | Section 3: `recover-admin`. |
| Signs in through **SSO** | Their identity provider owns the second factor. Fix it there. Keyorix cannot reset it (`user reissue-one-time-password` also refuses SSO users). |
| Is a **non-admin with local credentials**, no recovery code | Section 4: an administrator MFA reset (host command `admin reset-mfa`). |
| Is **locked out** after failed codes (the code is right, the account is refused) | Section 5. |

## 2. Self-service with a recovery code

Ten single-use recovery codes are printed once, when MFA is activated. The login and step-up
prompts for the authenticator code also accept an unused recovery code:

```
$ keyorix login --server https://localhost:8080 --ca-file certs/server.crt --username alice
Password:
Authenticator code (or an unused recovery code):
Logged in to https://localhost:8080 as alice.
```

A recovery code also replaces the lost factor. The two calls below re-check the user in `code`
with a current authenticator code **or an unused recovery code**, or in `password` with the
account password right after a passkey re-authentication. A recovery code is accepted only in
`code`: one sent in `password` is checked as a password, refused and not consumed. A user who lost the phone signs in
with one recovery code and spends a second one on `POST /api/v1/auth/mfa/disable`, then enrols
the new device (issue #4224). The rules for the recovery code there:

- It is consumed in the same transaction as the disable or the regenerate. If the change fails,
  nothing changes (the code stays unused, MFA stays on) and the answer is the same as for a wrong
  code.
- Every refusal is HTTP 400 `invalid code or password`, whether the code was wrong, already used
  or the change failed, and each one counts toward the account lockout exactly like a wrong
  authenticator code (section 5). A locked account is refused before the code is looked at, and
  the code stays unused.
- Two requests with the same code at the same time: one succeeds, the other is refused.
- FIPS 140-only mode (`GODEBUG=fips140=only`): authenticator codes are refused there (HTTP 503
  `TOTP is not available in FIPS mode`), recovery codes work exactly as above. On such an install a
  recovery code is the only self-service way off TOTP.
- The password alone is still refused on an account that has TOTP and no passkey re-authentication.

If the user has no recovery code left, use section 3 (global admin) or section 4 (anyone else).

The `keyorix` CLI has `mfa enroll`, `mfa activate` and `mfa stepup` only, so the three calls below go
through the web UI or the API (all require a bearer session; the session from the recovery-code
sign-in is enough):

- `GET /api/v1/auth/mfa/recovery-codes` returns `{remaining, total}` (inside `data`).
- `POST /api/v1/auth/mfa/recovery-codes/regenerate` issues ten new codes and invalidates every old
  one, used or not; its body is `{"code": ...}` (a current TOTP code or an unused recovery code) or
  `{"password": ...}` (accepted only right after a passkey re-authentication; never a recovery
  code). It keeps the
  current TOTP secret: a user who lost the phone disables instead.
- `POST /api/v1/auth/mfa/disable` takes the same body, clears the secret and all recovery codes,
  and ends the user's other sessions (the calling one stays), so a session on the lost phone stops
  working. The audit row `mfa.disabled` (and `mfa.recovery_codes_regenerated`) ends with
  `(method: recovery_code)` when a recovery code was the proof:

  ```bash
  curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"code":"ABCDE-FGHJK"}' https://keyorix.example.com/api/v1/auth/mfa/disable
  ```

  The user then enrols a new device:

  ```bash
  keyorix mfa enroll        # scan the otpauth:// URI or type the base32 secret into the new app
  keyorix mfa activate      # prompts for a code from the app and the account password
  ```

  `mfa activate` prints the new recovery codes once. Store them offline.

An authenticator code can be used once: a second request in the same 30-second window with the
same code is refused, so wait for the next code.

## 3. A global admin, with host access

`recover-admin` resets exactly one account and refuses an account that does not hold a
global-admin role. It needs the host **and** the recovery key
([j5-lost-admin.md](j5-lost-admin.md) §0 generates it ahead of time; the key is read from stdin
only):

```bash
# stop keyorix-server first: admin commands need the database to themselves
printf '%s' "$RECOVERY_KEY" | keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

It reactivates the account if needed, sets a one-time password (printed once, expires after
`security.recovery_one_time_password_ttl`, default 24h), **clears MFA enrolment, recovery codes
and every WebAuthn credential**, clears the login lockout and revokes every session of that
account. Nothing else is touched. Every run writes `admin.recover_admin` to the audit trail
(naming the host user who ran it) and notifies every current admin. The user then signs in with
the one-time password and, on a `require_mfa` install, gets a setup-only session of at most 15
minutes in which to set a new password and enrol a new factor
([j5-lost-admin.md](j5-lost-admin.md) §3-§5 has the exact prompts).

If no recovery key was ever generated, the command stops and tells you to run
`keyorix-server admin recovery-key rotate` first. On an install that has no key yet, `rotate`
generates the first one and prints it once (`--recipient` / `--output` have it age-encrypted
instead of printed; prefer a hybrid `age1pq1...` recipient, see [j5-lost-admin.md](j5-lost-admin.md)). Mind the terminal scrollback, and note that this makes the host plus the
master passphrase enough to recover an admin: that is the existing trust model.

`security.recover_admin.insecure_keyless_admin_recovery` skips the key. It exists for labs and demos;
do not turn it on for a pilot.

## 4. A non-admin with no recovery code: administrator MFA reset

First confirm who is asking, out of band (in person, a video call, a ticket from a known
address). A reset gives whoever receives the one-time password the account.

A reset is a **full credential reset, never "MFA off"**. In one transaction it removes the TOTP
secret, every recovery code and every WebAuthn credential, revokes every session and personal
access token of that account, replaces the password with a one-time password and marks the
account as owing a new MFA enrolment (`users.mfa_enrolment_required`). The audit row is written
in the same transaction: if it cannot be written, nothing is reset.

Refused, with nothing changed: a global admin (section 3), an SSO/SCIM account (its identity
provider owns the factor), a suspended or inactive account (reactivate it first) and a machine
identity (rotate its credentials instead).

### 4a. On the server host

Needs the host, the recovery key ([j5-lost-admin.md](j5-lost-admin.md) §0) and the database to
itself: the command holds the exclusive database-presence lock and refuses while the server runs.

```bash
# stop keyorix-server first
printf '%s' "$RECOVERY_KEY" | keyorix-server admin reset-mfa --user alice --recovery-key - --config ./keyorix.yaml
```

`--user` takes a username, an email address or a numeric user id. The command prints what it
removed and the one-time password, once (it expires after
`security.recovery_one_time_password_ttl`, default 24h). It writes `admin.reset_mfa` to the audit
trail naming the host user who ran it (a wrong key writes `admin.reset_mfa_failed` and changes
nothing), and leaves an in-app notification for the user and for every admin.

Give the one-time password to the user out of band. They sign in with it, set a new password and
enrol a new authenticator.

### 4b. Online, two administrators

With the server running, a reset needs two different global administrators, each with a second
factor of their own; neither may be the user being reset. Admin A opens the request, admin B
approves it within 24 hours. Each proves their own factor again in `code`: a current TOTP code,
or (passkey-only account) the account password right after a passkey re-authentication. There is
no `keyorix` CLI subcommand for this yet; use the API (or `curl`):

```bash
# admin A
curl -sS -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' \
  -d '{"user":"alice","reason":"lost phone","verified_by":"video","evidence":"call 10:05, ticket T-123","code":"123456"}' \
  https://keyorix.example.com/api/v1/mfa-reset-requests
# admin B: list (the request id is in the reply), then approve it; the response carries the
# one-time password, once, and it expires after security.one_time_password_ttl (default 72h)
curl -sS -H "Authorization: Bearer $TOKEN_B" 'https://keyorix.example.com/api/v1/mfa-reset-requests?status=pending'
curl -sS -H "Authorization: Bearer $TOKEN_B" -H 'Content-Type: application/json' \
  -d '{"code":"654321"}' https://keyorix.example.com/api/v1/mfa-reset-requests/7/approve
```

`verified_by` is `in_person`, `video`, `ticket` or `other`. A requester approving their own
request is refused and audited; an approved or cancelled request cannot be approved again; any
admin can cancel a pending one (`POST .../{id}/cancel`). If the install has no second eligible
admin, the request is refused and names `admin reset-mfa` (section 4a). Audit:
`mfa.reset_requested`, `mfa.reset_approved`, `mfa.reset`, `mfa.reset_cancelled`. Every admin is
notified when a request is opened, approved or cancelled; the user gets an in-app notice after
signing in. Admin B hands the one-time password to the user out of band.

Do not work around a refusal by editing `mfa_secrets` or `users` rows in the database: that skips
the audit trail for an authentication change and is not a path the product supports.

## 5. Refused despite a correct code: lockout, not MFA

Repeated failures lock an account or an address (HTTP 429 "Too many login attempts" for the
address budget). Clearing it touches nothing else: no password, MFA enrolment, session or role.
With the server stopped (or `--force` if you are certain it is safe):

```bash
keyorix-server admin clear-login-lockout --user alice@example.com --config ./keyorix.yaml
keyorix-server admin clear-login-lockout --ip 203.0.113.7 --config ./keyorix.yaml
```

At least one of `--user` / `--ip` is required (`--user` takes an email address or a numeric user
id, not a username); the run is audited as `admin.login_lockout_cleared`. With `--force` on a live
server the audit row says the exclusive lock was not held.
Also check the clock: a TOTP code is time-based, and a server or phone that is several minutes
off fails every code.

## 6. Verify and gaps

After any path: `keyorix audit logs --limit 20` shows the sequence (`mfa.disabled`,
`admin.recover_admin` or `admin.reset_mfa`, `mfa.enrolled`, `mfa.activated`, `auth.password_changed`).

Gaps:

- `users.mfa_enrolment_required` is recorded by every reset, but the account-setup gate does not
  read it yet: on an install with `security.require_mfa` off, a reset user is confined to the
  password change and is then not forced to enrol (RECOVERY-MFA-RESET-1 follow-up). Turn
  `require_mfa` on, or check `keyorix audit logs` for the user's `mfa.activated`.
- The CLI has no `mfa disable`, `mfa recovery-codes` or `mfa regenerate-recovery-codes`; they are
  web UI / API only (section 2).
