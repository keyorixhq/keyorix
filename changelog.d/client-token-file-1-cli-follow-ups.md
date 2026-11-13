### Fixed
- **`printf %s pw | keyorix login` no longer fails with EOF.** A final piped line without a trailing newline is now accepted by every prompt (username, password, confirmations); EOF is reported only when nothing at all was read. CRLF line endings are still stripped.

### Changed
- **`keyorix doctor` reports the token source from the same resolver the other commands use.** The `token from KEYORIX_TOKEN`, `KEYORIX_TOKEN_FILE` and `the credentials file` wording is unchanged. A token file that is unreadable, empty or too permissive is still reported as such, and the token is never printed.

### Testing
- A static guard (`TestNoDirectBufioOverStdin`) fails on `bufio.NewReader(os.Stdin)` / `bufio.NewScanner(os.Stdin)` anywhere in `cli/cmd` but `stdin_reader.go`, so a new prompt cannot bring back the lost-buffered-input bug (#3448, #4126).
- The CLI MFA login journey covers a piped login (username and password on stdin, code in `KEYORIX_MFA_CODE`).
