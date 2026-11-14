- **INV-VAULTSOURCE-non-2xx-read-is-an-error** `vaultsource`'s HTTP helpers `doRawRead` (KV
  read) and `do` (mount-version resolution, LIST) accept only HTTP 200 and the deliberately-
  handled 404, and `appRoleLogin` (POST auth/approle/login) accepts only HTTP 200; every other
  status is returned as an error and its body is never read/decoded.
  In particular a 3xx redirect — which the client refuses to *follow* (CheckRedirect =
  ErrUseLastResponse, see [[INV-VAULTSOURCE-walk-never-follows-redirects]]) — must not have its
  un-followed body parsed as the secret/list/mount response, or its `client_token` adopted as the
  session token. Why: a Vault behind a proxy/LB (or
  a compromised Vault) that answers a read with a 3xx would otherwise have its redirect body
  imported as the secret value, i.e. a fail-open mis-classification of a non-success response as
  success (task oracle (e); campaign FINDING F3). Guard: `TestWalk_RedirectReadBodyIsNotImported`,
  `TestWalk_Non200ReadIsAnError` and `TestAppRoleLogin_Non200IsAnError` (vault_redirect_test.go), plus the `{Route:2, Redir:1}` seed
  in `FuzzVaultSourceHostileWalk` (its O5 delivery oracle fires if a redirected read is imported).
