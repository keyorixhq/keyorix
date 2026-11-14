- **INV-NETUTIL-webhook-tier-except-loopback** `IsPrivateOrLinkLocalExceptLoopback` is
  exactly `IsPrivateOrLinkLocal` with loopback removed: it refuses every private, link-local,
  cloud-IMDS and RFC-6598 CGNAT (100.64.0.0/10) range, in every embedded-IPv4 IPv6 encoding
  (NAT64 well-known/local-use, IPv4-compatible, 6to4, Teredo), and permits loopback only —
  direct (127.0.0.0/8, ::1) and embedded (e.g. NAT64 of 127.0.0.1). This is the one webhook-tier
  SSRF policy the evidencesink, SIEM and notifychan dial guards delegate to, so a per-caller
  policy difference (loopback allowed) can never become an encoding or range gap. Why: V7 egress
  parity audit (F1 embedded-IPv4 decode gap, F2 CGNAT gap) — the three guards had each hand-rolled
  this on stdlib and drifted. Guard: `internal/netutil`
  `TestIsPrivateOrLinkLocalExceptLoopback` (refused/permitted vectors incl. CGNAT and embedded
  loopback) and `TestIsPrivateOrLinkLocalExceptLoopback_IsIsPrivateOrLinkLocalMinusLoopback`
  (equals `IsPrivateOrLinkLocal && !loopback` across an octet × encoding sweep); the
  cross-package parity is pinned by `internal/evidencesink`'s differential harness and
  `internal/core`'s `FuzzSSRFGuardDifferential`. **Not covered**: textual-spelling IP literals
  (decimal/octal/hex/trailing-dot) — `net.ParseIP` rejects all, so they never reach the
  classifier as an IP.
