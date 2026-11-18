### Testing
- **Hostile token-endpoint fuzzer for `golang.org/x/oauth2` on the SSO/OIDC login path.**
  New `fuzz/thirdparty/oauth2sso.FuzzOAuth2HostileTokenEndpoint` drives the real
  `(*oauth2.Config).Exchange` — as `core.CompleteSSO` drives it on the unauthenticated SSO
  callback — against a fuzzer-controlled loopback token endpoint that writes raw HTTP
  responses (arbitrary status / content-type / body, and a lying `Content-Length` for the
  truncation oracle). Oracles (all red/green-proven in `oracle_validation_test.go`): fails
  closed on a truncated response, never echoes the client secret in a returned error or
  token, yields a non-empty `access_token` on a nil-error Exchange, and stays air-gapped with
  bounded dials / response bytes / per-input allocation via the shared `resguard` resource
  helper. Closes a gap: no prior target exercised oauth2's token-response parser on our call
  path (existing SSO fuzzers cover the id_token JWT verification that runs after Exchange).
