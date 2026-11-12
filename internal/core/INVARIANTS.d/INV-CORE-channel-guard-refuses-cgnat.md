- **INV-CORE-channel-guard-refuses-cgnat** The notification-channel webhook guard
  `isChannelDisallowedIP` refuses RFC-6598 shared carrier-grade NAT space (100.64.0.0/10),
  including Alibaba Cloud's instance-metadata endpoint 100.100.100.200, in every embedded-IPv4
  IPv6 encoding — because it delegates to `netutil.IsPrivateOrLinkLocal` (the strict backend
  predicate, loopback refused too), whose canonical CIDR set includes 100.64/10, rather than the
  prior hand-rolled stdlib `ip.IsPrivate()` which did not. Complements
  [[INV-CORE-channel-guard-refuses-local-host]] (same predicate, same three call sites:
  `validateWebhookURL`, `validateWebhookSendTimeURL`, dial-time `escalationTransport`). Why: V7
  egress parity audit F2. Guard: `internal/core` `FuzzSSRFGuardDifferential` (drives
  `isChannelDisallowedIP` through every encoding and asserts parity with the raw-form verdict,
  which is now `true` for 100.64/10) and `internal/evidencesink`
  `TestEgressParity_WebhookTierCGNATGap`. **Not covered**: the `IsLinkLocal` tier
  (connect/OIDC) intentionally still permits CGNAT (on-prem/carrier deployments use it
  internally); this invariant is specific to the notification-channel guard.
