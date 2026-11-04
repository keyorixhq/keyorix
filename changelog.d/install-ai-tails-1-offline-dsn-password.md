### Security

- **`offline-install.sh setup --postgres-dsn` refuses a password in any letter case.** `Password=`, `PASSWORD=`, `pwd=`, `passwd=` and the URL forms (`user:password@`, `?Password=`) are refused like `password=`; the password goes in `secrets/db_password`. Guarded by `TestOfflineInstallRefusesPasswordInPostgresDSN`.

### Testing

- **`INSTALL-WITH-AI.md` guards tightened.** The secret-read rule is an allowlist of non-reading commands (an unknown command naming a secret path fails), and the page's pinned release must not be older than the newest release in `CHANGELOG.md`.
