- **INV-SECRETENV-secret-file-nonempty-and-bounded** `ReadFile` (the shared secret-file
  read path: `OpenRegular`->`ReadCapped`->`trimOneTerminator`->empty refusal) returns a
  value that is never longer than `MaxSecretFileSize`, equals `trimOneTerminator(content)`
  exactly when it succeeds, and ALWAYS errors when the trimmed content is empty -- a secret
  is never the empty string and the read path never corrupts or truncates content below the
  cap. Why: `secretenv.go` `readSecretFileJudged`/`ReadCapped` doc. Guard:
  `FuzzReadSecretFileRoundTrip`. Does NOT exercise non-regular files (OpenRegular's own
  tests) nor the >1 MiB size-cap boundary (ReadCapped unit tests; fuzz cannot reach it).
