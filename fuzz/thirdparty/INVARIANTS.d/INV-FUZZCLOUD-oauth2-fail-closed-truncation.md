- **INV-FUZZCLOUD-oauth2-fail-closed-truncation** golang.org/x/oauth2's
  `(*Config).Exchange`, as Keyorix drives it on the SSO/OIDC login callback
  (`core.CompleteSSO`, `internal/core/sso.go:255`), must fail CLOSED on a truncated token
  response: when the token endpoint declares a longer body than it delivers (a lying
  `Content-Length`, then close), Exchange must return an error, never a partial-success
  `*Token`. A nil-error Exchange must additionally carry a non-empty `access_token` — a
  silent empty-token success would hand an authenticated SSO session to a hostile/compromised
  IdP. Why: the token-endpoint response is network-controlled under the multi-tenant /
  customer-configured-SSO threat model, exactly like the cloud-SDK hostile-server targets;
  the id_token JWT verification that follows (`verifyIDToken`, covered by `FuzzVerifyIDToken`)
  only runs if Exchange returns a token at all. Guard: `FuzzOAuth2HostileTokenEndpoint`
  (`fuzz/thirdparty/oauth2sso`), truncation + success-invariant oracles, red/green-proven in
  `oracle_validation_test.go` (`TestOracle_Truncation_RedGreen`,
  `TestOracle_SuccessInvariant_RedGreen`), the green side confirmed end-to-end against the
  real library. Does NOT assert anything about TLS, the on-wire request, the id_token
  contents, or OIDC discovery — only Exchange's accept/reject and no-secret-echo behaviour on
  the raw token response.
