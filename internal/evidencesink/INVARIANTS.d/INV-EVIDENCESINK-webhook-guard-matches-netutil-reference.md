- **INV-EVIDENCESINK-webhook-guard-matches-netutil-reference** The evidence-webhook dial-time
  classifier `isDisallowedIP` refuses exactly what the webhook-tier netutil reference refuses:
  it delegates to `netutil.IsPrivateOrLinkLocalExceptLoopback`, so every private, link-local,
  cloud-IMDS and RFC-6598 CGNAT (100.64.0.0/10) target is refused in every embedded-IPv4 IPv6
  encoding (NAT64 well-known/local-use, IPv4-compatible, 6to4, Teredo), with loopback permitted
  (an evidence receiver may legitimately be local). This function is wired into the per-dial
  `netutil.Dialer` (`webhook.go`), so the guarantee holds at actual dial time, not only at
  construction. Why: V7 egress parity audit F1 — `isDisallowedIP` used a hand-rolled stdlib
  check that omitted the embedded-IPv4 decode its siblings apply, so a NAT64/6to4/Teredo/
  IPv4-compatible encoding of an internal/IMDS target was accepted (25 reproduced bypasses);
  and F2, the shared CGNAT gap. Guard: `internal/evidencesink`
  `TestEgressParity_EvidencesinkEmbeddedIPv4Gap` (no bypass vs. the siem sibling across all
  encodings), `TestEgressParity_WebhookTierCGNATGap` (refuses CGNAT like the reference),
  `TestEgressParity_OracleSoundness_RedProof` (the oracle fires on a planted decode hole and is
  clean on evidencesink) and the `FuzzEgressGuardParity` encoding-robustness control.
  **Not covered**: the object-store sink (`objectstore.go`) does no dial-time IP classification
  by design (self-hosted S3/MinIO are legitimately private); redirect-chain policy is a separate
  control (`refuseRedirect`).
