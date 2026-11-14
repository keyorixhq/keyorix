package faultops

// provisionSSOUser (internal/core/sso.go): SSO JIT provisioning for both SAML
// (CompleteSAML) and OIDC (CompleteSSO via ensureSSOUser). Driven through the SAML
// ACS op: the OIDC callback op signs in an existing account and never reaches JIT.
// Fixed by PARTIAL-COMMIT-NOV-2 (#3225).
func init() {
	registerUserCreateLostAckSite("provisionSSOUser", userCreateLostAckSite{op: "REST POST /auth/saml/{provider}/acs"})
}
