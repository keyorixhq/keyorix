- **INV-NETUTIL-tier-parity** The three IP-class egress tiers are one strict reference with
  exactly two documented, still-live relaxations, and nothing else. `IsPrivateOrLinkLocal`
  (the strict "private" tier) is the reference. `IsLinkLocal` (the "link-local" tier) differs
  from it only by PERMITTING private-but-not-link-local destinations (RFC-1918, loopback,
  0.0.0.0/8, RFC-6598 CGNAT, IPv6 ULA incl. fd00:ec2::254, in every embedded-IPv4 encoding),
  for on-prem/air-gapped OIDC issuers and Connect backends. `IsPrivateOrLinkLocalExceptLoopback`
  (the "webhook" tier, which `internal/audit/siem`'s `isDisallowedIP`/`DialDisallowed` also IS)
  differs from the reference only by PERMITTING loopback (direct and embedded), for an
  operator-run local receiver. Any other case where a tier (or the SIEM forwarder's predicate)
  permits a destination the reference refuses is a finding — including a silent regression of
  the SIEM predicate to a hand-rolled stdlib classifier (which would stop permitting loopback
  or start permitting CGNAT, the F1/F2 shape). Each relaxation is a policy choice stated at the
  predicate in `internal/netutil/dialer.go` (`linkLocalCIDRs`, `IsPrivateOrLinkLocalExceptLoopback`)
  and in the tier table of `docs/security/egress-inventory.md`.
  Why: every outbound site that refuses a destination by its IP class does so through one of
  these three predicates wired into a `netutil.Dialer`; guards that drift apart silently are the
  SSRF-parity failure this harness exists to catch (V7-EGRESS-PARITY-1). The reference's ground
  truth is `internal/fuzzutil/egressref.Addr.Private` (octet arithmetic, no netutil call), so a
  netutil CIDR/encoding bug cannot define away the expectation it is checked against.
  Guard: `internal/netutil` (external test package) `TestEgressTierParity_FixedSeeds` (O1/O2/O4
  over a deterministic corpus), `TestEgressTierParity_NoStaleRows` (O3: every
  INTENTIONAL-DIFFERENCES row corresponds to a live divergence), `TestEgressTierParity_TableWellFormed`,
  `TestEgressTierParity_RebindAnswerSetValidated` (the whole resolved answer set is validated and
  the dial is pinned to the validated literal IP), and `FuzzEgressTierParity`. Red/green proven
  (V7-EGRESS-PARITY-1, throwaway worktree, never committed): dropping the embedded-IPv4 decode in
  `IsLinkLocal` turns O2 red; validating only the first resolved answer turns the rebind oracle
  red; dialing the hostname instead of the pinned IP turns O4 red; each reverts to green.
  **Not covered**: real DNS/TLS/HTTP-2, egress proxies from the environment, textual-only literal
  spellings (`net.ParseIP` rejects them uniformly), the per-package redirect `CheckRedirect`
  policy (unexported, each package tests its own; the dial-time re-validation every redirect hop
  relies on IS exercised here because `Dialer` re-validates on every `DialContext`), and the
  pinned-endpoint (S08) / allow-list (S26) mechanisms, which make no per-address refusal decision.
