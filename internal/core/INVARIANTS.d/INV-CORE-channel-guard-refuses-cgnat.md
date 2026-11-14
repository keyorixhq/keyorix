- **INV-CORE-channel-guard-refuses-cgnat** The notification-channel webhook guard
  `isChannelDisallowedIP` refuses RFC-6598 shared carrier-grade NAT space (100.64.0.0/10),
  including Alibaba Cloud's instance-metadata endpoint 100.100.100.200, in every embedded-IPv4
  IPv6 encoding — because it delegates to `netutil.IsPrivateOrLinkLocal` (the strict backend
  predicate, loopback refused too), whose canonical CIDR set includes 100.64/10, rather than the
  prior hand-rolled stdlib `ip.IsPrivate()` which did not. Complements
  [[INV-CORE-channel-guard-refuses-local-host]] (same predicate, same three call sites:
  `validateWebhookURL`, `validateWebhookSendTimeURL`, dial-time `escalationTransport`). Why: V7
  egress parity audit F2. Guard: `internal/core` `TestIsChannelDisallowedIP_RefusesCGNAT`
  (CGNAT direct, IPv4-mapped and NAT64 forms refused; 100.63.255.255 and 100.128.0.1 allowed)
  and `TestValidateWebhookURL_RefusesCGNAT` (literal and resolved-hostname refusal at
  `validateWebhookURL`, literal refusal at `validateWebhookSendTimeURL`); both are red on a
  revert to the stdlib check. `FuzzSSRFGuardDifferential` only asserts that every encoding gets
  the raw form's verdict, so it does not by itself pin the CGNAT refusal. **Not covered**: the `IsLinkLocal` tier
  (connect/OIDC) intentionally still permits CGNAT (on-prem/carrier deployments use it
  internally); this invariant is specific to the notification-channel guard.
