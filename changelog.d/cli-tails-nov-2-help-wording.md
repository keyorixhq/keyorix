### Fixed
- **`secret create --help` no longer shows a made-up value name for `--environment`.** Cobra reads the first backquoted words of a flag description as its placeholder, so the hint to run "keyorix project environments <project-id>" printed as the flag's type; the same happened for `secret acl revoke --acl`. Both now use plain quotes (`docs/cli-reference.md` and the man page regenerated).

### Testing
- **Help-text guards for the secret-flag refusal.** `TestHelpNamesNoRefusedFlag` renders the help of every command and fails when a description, example or long text names a flag that `refusedSecretFlags` hides and refuses (`--password`, `--mfa-code`, `--value`, ...; a flag the command really offers is not counted); `TestFlagUsageHasNoBacktickPlaceholder` fails on a backtick in any visible flag description. On current main no help names a refused flag, so the first test pins that state.
