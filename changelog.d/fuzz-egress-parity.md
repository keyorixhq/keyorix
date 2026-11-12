### Testing
- Added a differential egress-guard SSRF parity harness in `internal/evidencesink`
  (`FuzzEgressGuardParity` plus table tests) that drives one address — in every
  embedded-IPv4 IPv6 encoding (NAT64 well-known/local-use, IPv4-compatible, 6to4,
  Teredo), native link-local literals and the cloud-metadata IPs — through the
  package's dial-time classifier and compares each verdict to the `netutil`
  reference and the sibling `siem.DialDisallowed` guard, with an oracle-soundness
  red-proof that plants a decode hole in a scratch copy of the guard. Two
  quarantined red tests document the gaps it found (see below).

### Security
- Documented (issue-ready, no code change) two egress-guard parity divergences
  from the `netutil` reference found by the new harness: evidencesink's dial-time
  `isDisallowedIP` omits the embedded-IPv4 decode its siblings apply, so a
  NAT64/6to4/Teredo/IPv4-compatible encoding of a private/link-local/IMDS address
  bypasses it (F1); and all webhook-tier guards classify with stdlib
  `ip.IsPrivate()`, which excludes RFC-6598 CGNAT (100.64.0.0/10), leaving Alibaba
  cloud IMDS at 100.100.100.200 reachable (F2).
