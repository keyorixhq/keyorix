### Security
- **Unlocking a user and resuming a secret no longer happen without an audit record.**
  `POST /api/v1/users/{id}/unlock` (and the gRPC equivalent) cleared the login lockout first and wrote
  `account.unlocked` afterwards on a best-effort basis, and `ResumeSecret` did the same with
  `secret.resumed`, so an audit-log fault left an unrecorded lift of a brute-force refusal or a
  suspension. The change and its audit row now commit in one transaction: if the audit write fails the
  lockout stays set (or the secret stays suspended) and the call returns the standard 500 error body, as
  `keyorix-server admin clear-login-lockout` already did. The error contract is unchanged.
