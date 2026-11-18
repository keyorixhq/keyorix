// Package oauth2sso holds a hostile-token-endpoint fuzz target for
// golang.org/x/oauth2's authorization-code Exchange, driven exactly as Keyorix's
// SSO/OIDC login path drives it.
//
// Keyorix is the OAuth2 CLIENT. On every SSO callback, core.KeyorixCore.CompleteSSO
// (internal/core/sso.go:255) calls (*oauth2.Config).Exchange against the IdP's token
// endpoint. The Config is built from OIDC discovery (server/wire_sso.go:220) with no
// AuthStyle set, so oauth2 auto-detects the style — which means a single Exchange can
// perform up to two HTTP round-trips to the token endpoint. The response bytes of those
// round-trips are network-controlled: under the standard multi-tenant / customer-
// configured-SSO threat model the IdP (or a party that has compromised it) is hostile,
// exactly like the fuzz/thirdparty database-driver and internal/connect cloud-connector
// hostile-server campaigns.
//
// No existing fuzz target drives golang.org/x/oauth2's token-response parser on our call
// path (the existing SSO fuzzers — FuzzVerifyIDToken, FuzzOIDCIDTokenSingleConstraint... —
// cover the id_token JWT verification that runs AFTER Exchange, not the oauth2 HTTP
// token-response parse itself). This target fills that gap.
//
// Everything runs on a loopback listener; no real network. The target is test-only.
package oauth2sso
