- **INV-NOTIFYCHAN-webhook-guard-matches-netutil-reference** The notification-webhook dial-time
  classifier `isDisallowedIP` refuses exactly the webhook-tier netutil reference: it delegates to
  `netutil.IsPrivateOrLinkLocalExceptLoopback`, so every private, link-local, cloud-IMDS,
  unspecified/0.0.0.0/8 and RFC-6598 CGNAT (100.64.0.0/10) target is refused in every
  embedded-IPv4 IPv6 encoding, with loopback permitted (a dev receiver may legitimately be
  local). Wired into the per-dial `netutil.Dialer` and shared by `validateEndpoint`, `NewWebhook`
  and `NewChat`. Why: V7 egress parity audit F2 — the guard classified with stdlib
  `ip.IsPrivate()`, which excludes CGNAT. Guard: `internal/notifychan`
  `TestSSRFMatrix_EndpointIPLiteralForms` and `TestSSRFMatrix_DialGuardRefusesLiteralForms`
  (literal refuse/allow matrix incl. unspecified and embedded forms), with the CGNAT and
  cross-guard parity pinned by `internal/evidencesink`'s differential harness. **Not covered**:
  redirect-chain policy (`refuseRedirectDowngrade`) and URL redaction are separate controls.
