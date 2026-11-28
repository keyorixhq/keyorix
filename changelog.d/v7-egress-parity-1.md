### Testing
- **Single cross-guard egress tier-parity harness.** Added `FuzzEgressTierParity` and its
  fixed-seed tests (`internal/netutil`, external test package): one differential harness that
  drives every IP-class egress guard — the netutil link-local / webhook / private tiers and the
  SIEM forwarder's exported predicate — through the same probe table and the real
  `netutil.Dialer` entry point with an injected resolver and an injected recording dialer. A
  destination the strict reference refuses must be refused by every guard unless a live,
  documented INTENTIONAL-DIFFERENCES row licenses it (O1/O2); every row must still correspond to
  a real divergence (O3, no stale rows); and no real connection is made (O4). Complements the
  per-site V7-GAP-1 transport targets, which each check one site's wiring, with the cross-guard
  question of whether the tiers agree except where documented.
