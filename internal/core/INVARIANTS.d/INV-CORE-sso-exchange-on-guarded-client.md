- **INV-CORE-sso-exchange-on-guarded-client** The OIDC authorization-code exchange in
  `CompleteSSO` runs only on the provider's `SSOProvider.HTTPClient`, put in the exchange
  context as `oauth2.HTTPClient`; a provider without one is refused with a fixed error
  (`errSSONoExchangeClient`), never left to x/oauth2's `http.DefaultClient` fallback. The
  wiring (`server/wire_sso.go` `buildSSOProviders`) sets it to `ssoIdPHTTPClient`, the
  discovery client: `oidcDiscoveryTransport` (netutil link-local dial guard) and
  `noDiscoveryCrossOriginRedirect` (same origin, no https downgrade, at most 3 requests), so
  a 307 cannot resend the code, PKCE verifier and client credentials to another origin. At
  discovery the `token_endpoint` must be on the issuer's host or a host listed in
  `sso.providers[].token_endpoint_hosts`, and https unless the issuer is http on loopback
  (`validateTokenEndpoint`). Why: #4738 (V7-GAP-1 egress inventory, finding F2): the
  exchange used `http.DefaultClient`, so a compromised IdP's discovery document or redirect
  could aim the server's POST, with the client secret, at an internal or metadata address.
  Guard: `server` `TestSSOTokenEndpointOffIssuerHostNeverReceivesExchange` and
  `TestSSOTokenExchangeCrossOriginRedirectNotFollowed` (real discovery → `buildSSOProviders`
  → `BeginSSO` → `CompleteSSO`; assert a second listener receives nothing; red on the
  pre-fix code), `TestSSOTokenExchangeSameOriginControl` (green control),
  `TestSSOExchangeClientIsTheDiscoveryClient` (transport identity and redirect verdicts
  equal to discovery's), `FuzzSSOExchangeTransportEgressParity` (the built client's dial
  hook against `internal/fuzzutil/egressref`), `FuzzDiscoverOIDCHostile` (token_endpoint
  host and scheme oracle). **Not covered**: a dial to a real link-local address end to end
  (no test can listen there; the fuzz target reads the guard's refusal with a cancelled
  context); DNS rebinding of the issuer's own host to a link-local address is refused by the
  dial guard but has no resolver seam to drive it; an operator-listed host is trusted as
  listed; the `authorization_endpoint` is not host-checked (the server never dials it, the
  browser is redirected there); with an egress proxy the dial targets the proxy.
