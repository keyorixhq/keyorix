### Security

- `admin encryption rotate`, `upgrade-aad`, `rotate-kek` and `migrate-provider` refuse missing key files before they open the database, so on SQLite a run from the wrong directory no longer leaves an empty database file behind.
- `admin encryption auth-encryption status`, `validate`, `rotate` and `migrate` refuse missing key files before they open the database (same SQLite empty-file defect), and all five auth-encryption commands now close the database they open.

### Documentation

- `docs/operator/startup-refusals.md`: the "Wrong master passphrase" entry shows the extra line the error carries when an interrupted `rotate-kek` or `migrate-provider` left a file in the key directory, and names the key files by their config keys (`dek_path`, `salt_path`).
