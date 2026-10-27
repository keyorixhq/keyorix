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
| Still has an **unused recovery code** | Section 2: self-service, no operator needed. |
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

Then, in the same session, replace the lost factor before the codes run out. The `keyorix`
CLI has `mfa enroll`, `mfa activate` and `mfa stepup` only, so these two go through the web UI
or the API (all require a bearer session):

- `GET /api/v1/auth/mfa/recovery-codes` returns `{remaining, total}`.
- `POST /api/v1/auth/mfa/recovery-codes/regenerate` issues ten new codes and invalidates every old
  one, used or not; it needs a current code **or the account password**.
- `POST /api/v1/auth/mfa/disable` (`{"code": ...}` or `{"password": ...}`) clears the secret and
  all recovery codes, and ends the user's other sessions. The user then enrols a new device:

  ```bash
  keyorix mfa enroll        # scan the otpauth:// URI or type the base32 secret into the new app
  keyorix mfa activate      # prompts for a code from the app and the account password
  ```

  `mfa activate` prints the new recovery codes once. Store them offline.

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

At least one of `--user` / `--ip` is required; the run is audited as `admin.login_lockout_cleared`.
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
