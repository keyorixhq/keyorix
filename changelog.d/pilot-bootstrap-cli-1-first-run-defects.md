### Fixed
- **`keyorix login --help` no longer names flags the CLI refuses.** The help told the
  reader the password comes from `--password` and mentioned `--mfa-code`; both are
  refused (a secret on the command line shows in `ps`). It now names only
  `KEYORIX_PASSWORD[_FILE]`, `KEYORIX_MFA_CODE[_FILE]` and the prompt. A new test
  (`TestNoHelpNamesARemovedFlag`) fails if any command's help names a flag that the
  CLI refuses and no command still accepts.
- **`keyorix system init --ca-file <pem>` now prints a `login` next step that works.**
  The printed line omitted the CA file, so pasting it against the default self-signed
  TLS server failed with "cannot trust the TLS certificate" (exit 6). It now repeats
  the `--ca-file` the reader just used.
