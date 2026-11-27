## OIDC providers whose token endpoint is on another host are skipped at start-up

Since #4738, OIDC discovery checks the `token_endpoint` the way it already checked
`jwks_uri`: it must be on the issuer's host and use https (http only for an http
loopback issuer). The code exchange also runs on the guarded discovery client now, so it
no longer follows a redirect to another origin.

Who is affected: an identity provider that serves its token endpoint from a different
domain than its issuer (Amazon Cognito is the common case). Okta, Microsoft Entra ID,
Keycloak, Auth0 and other providers with the token endpoint on the issuer host are not
affected.

What you see: at start-up the log has `SSO provider "<name>" discovery failed: discovery
token_endpoint host "<host>" is neither the issuer host "<issuer host>" nor listed in
token_endpoint_hosts; skipping`, and that provider is missing from the login page.

What to do: add the token endpoint's host to the provider's
`sso.providers[].token_endpoint_hosts` (see `docs/configuration.d/sso__providers__token_endpoint_hosts.md`)
and restart. No change is needed for any other provider.
