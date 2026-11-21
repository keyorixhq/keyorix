### Testing
- **RL1 lockout / rate-limit metamorphic fuzzers.** Added
  `FuzzSourceRateLimitKeyEquivalence` (server/middleware): a metamorphic fuzzer
  over the source-attribution pipeline every per-source rate limiter / lockout
  counter keys on (`middleware.ClientIP` extraction → `core.CanonicalIP`), proving
  equivalent IP presentations (ephemeral port, bracketed/bare IPv6, upper/lower
  hex, zero-expanded, IPv4-mapped) collapse to one bucket, that an untrusted peer's
  forwarding headers can never move the key off the TCP peer (anti-spoof +
  anti-targeted-DoS), and that a left-prepended X-Forwarded-For spoof behind a
  trusted proxy never changes the attributed client. Added
  `FuzzAuthFallbackLimiterBounded` (internal/core): a resguard-metered
  bounded-memory oracle over the in-memory `authFallbackLimiter`, asserting its
  `byID`/`byStored` index maps stay bounded by the cap (exactly one entry per live
  attempt) under a flood of up to 65 536 distinct keys — a memory-DoS class the
  existing `size()`-only assertion is structurally blind to. Both carry red/green
  proofs; no production code changed.
