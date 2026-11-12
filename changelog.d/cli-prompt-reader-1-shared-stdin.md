### Fixed
- **`keyorix login`, `mfa activate`, `mfa step-up` and the delete/revoke confirmations lost every piped line after the first.** Each prompt built its own buffered reader over stdin, which swallowed the rest of the pipe, so `printf 'user\npass\n' | keyorix login` failed with `read password: EOF` (#3448). All prompts now share one reader. Terminal password entry (no echo) is unchanged.
