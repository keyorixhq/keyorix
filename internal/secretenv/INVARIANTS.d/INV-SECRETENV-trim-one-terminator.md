- **INV-SECRETENV-trim-one-terminator** `trimOneTerminator` removes at most ONE trailing
  line terminator: its result is always a prefix of the input and the removed suffix is
  exactly one of `""`, `"\n"`, `"\r"`, `"\r\n"`. This is what keeps
  `*_MASTER_PASSWORD_FILE` and `--passphrase-file` deriving the same KEK from the same
  bytes. Why: `secretenv.go` `trimOneTerminator` doc. Guard: `FuzzTrimOneTerminator`
  (exact-removed-suffix oracle), with `FuzzReadSecretFileRoundTrip` confirming the read
  path applies exactly this and nothing else. Does NOT assert cross-package agreement with
  `internal/crypto/passphrase.go`'s copy of the rule (a drift test belongs there).
