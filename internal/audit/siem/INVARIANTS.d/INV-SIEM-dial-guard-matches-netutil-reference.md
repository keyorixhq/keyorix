- **INV-SIEM-dial-guard-matches-netutil-reference** The SIEM-forwarder dial-time classifier
  `isDisallowedIP` (exported read-only as `DialDisallowed`) refuses exactly the webhook-tier
  netutil reference: it delegates to `netutil.IsPrivateOrLinkLocalExceptLoopback`, so every
  private, link-local, cloud-IMDS and RFC-6598 CGNAT (100.64.0.0/10) target is refused in every
  embedded-IPv4 IPv6 encoding, with loopback permitted (a SIEM collector may legitimately be
  local). Wired into the per-dial `netutil.Dialer` in `newForwarder`, so it holds at dial time.
  Why: V7 egress parity audit F2 — the guard classified with stdlib `ip.IsPrivate()`, which
  excludes CGNAT, so Alibaba cloud IMDS (100.100.100.200) was reachable. Guard:
  `internal/core` `FuzzSSRFGuardDifferential` (drives `siem.DialDisallowed` through every
  encoding and asserts parity with the raw-form verdict) and `internal/evidencesink`
  `TestEgressParity_SiemIsEncodingRobust` / `TestEgressParity_WebhookTierCGNATGap` (siem refuses
  CGNAT like the reference). **Not covered**: redirect-chain policy (`refuseRedirect`) and the
  durable spool are separate concerns.
