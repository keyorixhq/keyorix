### Fixed

- Web: the Projects page no longer shows **New Project**, edit and delete to a session that lacks `secrets.write` / `secrets.delete` (for example a `project_viewer`), instead of offering actions the server refuses (#3739).
- Web: the two-factor setup dialog, including the forced first-login enrolment, now shows the `otpauth://` URI as a QR code drawn in the browser (no network request); the text setup key and the "Open in authenticator app" link remain as fallbacks (#3738).
- Dashboard: "Inactive users" no longer counts an account created within the last 30 days that has not logged in yet, so a fresh install reads 0 instead of 1 (#3740).
