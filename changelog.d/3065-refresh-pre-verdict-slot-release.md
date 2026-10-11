### Security
- **A storage fault while checking a session token no longer spends the per-IP
  login budget on `POST /auth/refresh`** (#2880). When the session lookup or the
  owner lookup fails before the token has been judged, nothing was guessed, so
  the request now returns its slot instead of counting as a failed attempt (a
  client behind a flaky database could lock its own IP out of logging in). The
  refusal is the same 401 as before. A fault after the token was accepted (the
  rotation itself, the reuse revocation) still keeps the slot, so a valid token
  is never cheaper than a wrong one; that behaviour is now pinned by-design in
  the fault-injection oracle.
