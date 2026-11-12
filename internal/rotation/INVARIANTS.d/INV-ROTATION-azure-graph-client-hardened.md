- **INV-ROTATION-azure-graph-client-hardened** The Azure AD rotation executor's Microsoft Graph
  HTTP client (`azureGraphHTTPClient`) is hardened like the repo's other outbound clients, not a
  bare `http.Client`: it refuses every redirect (`refuseAzureGraphRedirect`, so a 30x from a
  compromised or MITM'd upstream cannot bounce the bearer-token-bearing request to another host —
  the stdlib default follows up to 10 to any host) and dials through a `netutil.Dialer` that
  refuses link-local targets (`netutil.IsLinkLocal`, including cloud IMDS 169.254.169.254).
  The Graph host is the hard-coded public constant `azureGraphBase`, so both are defence in
  depth, closing the last outbound client that lacked them. Why: V7 egress parity audit H1.
  Guard: `internal/rotation` `TestAzureGraphHTTPClient_RefusesRedirects` (a two-hop loopback
  redirect never reaches the second server) and `TestAzureGraphHTTPClient_RefusesLinkLocalDial`
  (a dial to 169.254.169.254 is refused by the guard before any socket opens). **Not covered**:
  the ambient `DefaultAzureCredential` token acquisition and the `ValidateAzureRef` path
  validation are separate controls; the AWS IAM executor uses the AWS SDK's own transport.
