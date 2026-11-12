# internal/netutil invariants

Read this before changing anything in `internal/netutil`. This package is the single
SSRF-safe egress substrate: the per-dial resolve-and-validate `Dialer` (closing the
DNS-rebinding gap G48), the embedded-IPv4 decode shared by every classifier, and the
canonical "disallowed as an SSRF target" predicates every outbound client delegates to —
`IsPrivateOrLinkLocal` (backend tier, even loopback refused), `IsLinkLocal` (narrow tier,
on-prem/RFC-1918 permitted) and `IsPrivateOrLinkLocalExceptLoopback` (webhook tier, loopback
permitted).

Format: `INV-NETUTIL-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-NETUTIL-<slug>.md`, one per file.
