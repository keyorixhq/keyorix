### `sso.providers[].token_endpoint_hosts`

List of host names, default empty. Extra hosts an OIDC provider's discovered
`token_endpoint` may be on, besides the issuer's own host. The token endpoint receives
the provider's `client_id`, `client_secret` and each login's authorization code, so at
start-up Keyorix refuses a discovery document whose `token_endpoint` is on any other
host and skips that provider with a log line naming both hosts. The endpoint must use
https; plain http is accepted only when the issuer itself is http on loopback (a dev
setup). Host names are compared case-insensitively and without the port; list host
names, not URLs.

Set it only for an identity provider that serves its token endpoint from a separate
domain, for example Amazon Cognito (issuer on `cognito-idp.<region>.amazonaws.com`,
token endpoint on your `<domain>.auth.<region>.amazoncognito.com` domain):

```yaml
sso:
  enabled: true
  providers:
    - name: cognito
      issuer: https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_EXAMPLE
      client_id: <client id>
      redirect_url: https://keyorix.example.com/auth/sso/cognito/callback
      token_endpoint_hosts:
        - example.auth.eu-west-1.amazoncognito.com
```

The code exchange itself runs on the same guarded client as discovery: it never dials
a link-local (cloud metadata) address and follows a redirect only within the same
origin, without downgrading https.
