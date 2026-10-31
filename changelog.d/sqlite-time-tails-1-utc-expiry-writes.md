### Fixed

- On SQLite, a risk exception or a Connect per-reference grant created with an `expires_at` that carries a UTC offset other than the server's own (for example `2027-01-01T10:00:00+02:00` on a UTC server) was stored with that offset as text, and every later listing of risk exceptions or Connect reference grants failed with a 500. The expiry is now stored as the same instant in UTC, as on PostgreSQL.
- On SQLite, an invitation, its setup link and an access request created on a server whose host time zone is not UTC stored their expiry and creation time in the host zone, so a project invitation's expiry did not order against the UTC clock the expiry checks use. They are now stored in UTC.
