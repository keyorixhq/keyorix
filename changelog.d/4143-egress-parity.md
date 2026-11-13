### Security
- **Evidence-webhook SSRF guard now decodes embedded-IPv4 encodings (F1).**
  `internal/evidencesink`'s dial-time classifier used a hand-rolled stdlib check
  that, unlike its siblings, did not decode NAT64 / IPv4-compatible / 6to4 /
  Teredo encodings of an IPv4 address, so those encodings of a private,
  link-local or cloud-IMDS target were accepted at dial time. It now delegates to
  the shared `netutil.IsPrivateOrLinkLocalExceptLoopback` predicate, which decodes
  every embedded form, so the evidence pack and its bearer token can no longer be
  POSTed to an internal host reached through such an encoding.
- **Webhook-tier egress guards now refuse RFC-6598 CGNAT (100.64.0.0/10) (F2).**
  The `internal/evidencesink`, `internal/audit/siem`, `internal/notifychan` and
  `internal/core` notification-channel guards classified with stdlib
  `ip.IsPrivate()`, which excludes shared carrier-grade NAT space, leaving Alibaba
  Cloud's instance-metadata endpoint (100.100.100.200) reachable. All four now
  route through the shared `netutil` predicates, whose canonical CIDR set already
  includes 100.64/10. The `IsLinkLocal` tier (connect/OIDC) is intentionally left
  permitting CGNAT, where on-prem/carrier deployments legitimately use it
  internally.

### Changed
- **Azure AD rotation Graph client is now hardened like the repo's other
  outbound clients (H1).** `internal/rotation/azure.go`'s Microsoft Graph client
  gained a redirect policy that refuses all redirects and a `netutil` dialer that
  refuses link-local targets. It still honours `HTTPS_PROXY`/`NO_PROXY` (the
  guard then checks the proxy address). The Graph host is a hard-coded public constant, so
  this is defence in depth against a compromised or man-in-the-middled upstream,
  bringing the one remaining unhardened outbound client in line with
  connect/notary/operator.

### Testing
- Added a differential egress-guard SSRF parity harness in `internal/evidencesink`
  (`FuzzEgressGuardParity` plus table tests) that drives one address — in every
  embedded-IPv4 IPv6 encoding (NAT64 well-known/local-use, IPv4-compatible, 6to4,
  Teredo), native link-local literals and the cloud-metadata IPs — through the
  package's dial-time classifier and compares each verdict to the `netutil`
  reference and the sibling `siem.DialDisallowed` guard, with an oracle-soundness
  red-proof that plants a decode hole in a scratch copy of the guard. The two
  reproducers that found F1/F2 are now active green regression guards (they
  reported 25 embedded-encoding bypasses and the CGNAT divergences before the
  fix). Added `netutil` unit coverage for the new
  `IsPrivateOrLinkLocalExceptLoopback` predicate and red/green egress tests for
  the Azure Graph client.
