### Security
- **A suspended inviter's pending invitation no longer grants on accept (#4507).** Accepting a
  project-scoped invitation, or a global invite's project assignments, used the inviter's
  authority without checking that the inviter's account was still active. The accept is now
  refused before the account is created, so the same link works again once the inviter is
  reactivated.
- **Re-authentication re-reads the account lockout after the credential matched (#2888).** A
  correct code or password could pass re-auth (MFA disable, recovery-code regeneration, email
  change) and clear the failed-login counter on an account a concurrent burst had just locked.
  It now answers like a wrong code, as login, MFA verify, step-up and WebAuthn already did.
- **Trusted-proxy parsing (#4520).** A bare IPv4-mapped trusted proxy (`::ffff:1.2.3.4`) was
  parsed as the IPv6 network `::/32`, trusting `::1` and every other `::/32` peer to set
  forwarding headers; it now covers exactly that host. With `X-Forwarded-For` absent, an
  `X-Real-IP` value that is itself a trusted proxy is no longer taken as the client IP. The same
  `::ffff:a.b.c.d` parsing bug made a PAT or machine-token network allowlist entry mean `::/32`
  (admitting `::1`, refusing the intended host); new entries are stored as the IPv4 host, and
  entries already stored in that exact shape (`::ffff:a.b.c.d/32`) are read as that host. Any
  other stored `::ffff:` entry with a prefix below 96 no longer matches anything (it matched no
  IPv4 client before); re-issue such a token with plain IPv4 CIDRs.
- **Core refuses an owner without `secrets.write` on tags, description and move (#4508).** Defence
  in depth: REST already refused these.

### Changed
- **`server.http.allowed_origins` refuses a `*` inside an entry (#4382).** `https://*` and
  `https://*.example.com` were accepted and treated as patterns by the CORS layer, giving every
  matching origin a credentialed grant. The same applies to a `*` in `server.http.domain`, the
  default origin when `allowed_origins` is empty. List each origin explicitly. A configuration
  that used such a value now fails to start, naming the setting (see UPGRADING.md 6zb).

### Fixed
- **The audit page's failed-attempts filter includes failed second factors (#3363).** The
  dashboard's "Failed Second Factors" card now lands on a list that shows them.
