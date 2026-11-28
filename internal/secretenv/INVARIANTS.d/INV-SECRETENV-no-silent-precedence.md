- **INV-SECRETENV-no-silent-precedence** `Lookup`/`LookupChecked` with BOTH `NAME` and
  `NAME_FILE` set returns a hard error with `found=false` and an empty value -- it never
  silently resolves to either scope -- and that error carries neither the env value nor the
  file content. With only `NAME` set it resolves to exactly the env value, never the file
  scope. Why: `secretenv.go` DEPLOY-2 decision 1 ("No silent precedence"). Guard:
  `FuzzLookupPrecedenceFailClosed` (canary-tagged, fail-closed). Does NOT judge the file's
  permissions/owner (that is `FuzzCheckInfoNeverAcceptsUnsafe` / the permission matrix) nor
  the file-only round-trip value (existing `secretenv_test.go`).
