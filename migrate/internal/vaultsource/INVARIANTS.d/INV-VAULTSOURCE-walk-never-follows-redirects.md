- **INV-VAULTSOURCE-walk-never-follows-redirects** The HTTP client `vaultsource.New` builds
  sets `CheckRedirect` to return `http.ErrUseLastResponse`, so `Walk` (and every request it
  makes — mount-version resolution, LIST, READ, AppRole login) never follows a 3xx redirect
  to another host. A response-controlled `Location` must never cause a request to an address
  the operator did not configure, so a compromised or misconfigured Vault can never redirect
  the live token to an attacker endpoint. Why: a credential-bearing first-contact request must
  fail closed on redirect; hostile-source fuzzing of the import path (task V2). Guard:
  `FuzzVaultSourceHostileWalk` — its hostile server injects redirects (to a sentinel internal
  address and self-loops) and the target asserts the sentinel receives zero requests and no
  served record is `Followed` (vault_hostile_fuzz_test.go, via the harness O9 oracle).
  NOTE: this covers redirect *following* only. The companion rule — a 3xx that is NOT followed
  must also never have its body parsed as the secret — is a separate invariant,
  [[INV-VAULTSOURCE-non-2xx-read-is-an-error]] (campaign FINDING F3, now fixed).
