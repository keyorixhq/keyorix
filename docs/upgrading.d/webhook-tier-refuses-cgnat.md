## Outbound webhooks to 100.64.0.0/10 (CGNAT) are now refused

**Who is affected:** deployments that send a notification channel, a notification webhook or chat
message, an audit SIEM forward or an evidence webhook to an address in RFC 6598 shared address
space, 100.64.0.0/10. A common case is a receiver reached over a Tailscale or carrier-grade NAT
address (100.x.y.z).

**Old behaviour:** these guards used Go's `ip.IsPrivate()`, which does not include 100.64.0.0/10,
so such a receiver was reachable. So was Alibaba Cloud's instance-metadata endpoint,
100.100.100.200, which is why this changed.

**New behaviour:** the address is refused like any RFC 1918 address, directly and in every
IPv6 form that embeds it (`::ffff:100.64.0.1`, `64:ff9b::6440:1`, ...). The check runs when the
URL is saved and again on every dial, so an existing receiver on 100.64.0.0/10 starts failing at
send time after the upgrade. The error says the target resolves to a private/link-local address.

**What to do, before upgrading:** look for receivers on 100.64.0.0/10 in your channel URLs and in
the `audit.siem`, `evidence_delivery.webhook` and `notifications.webhook` endpoints.

- Move the receiver to a public address or a hostname that resolves to one, where you can.
- For an audit SIEM, evidence webhook or notification webhook that must stay on the internal
  network, set its existing opt-out: `audit.siem.insecure_allow_private_network_siem_target`,
  `evidence_delivery.webhook.insecure_allow_private_network_evidence_target` or
  `notifications.webhook.insecure_allow_private_network_notify_target`. It turns off the
  private-address check for that endpoint, CGNAT included.
- Notification channels and the notifications chat sink have no opt-out. A receiver for them
  must be on a public address.

The connect and OIDC outbound clients only refuse link-local addresses and are not affected.
