### Testing
- **SMTP AUTH iteration-cap test no longer depends on the clock (SMTP-TIMING-1).**
  `TestSCRAMRefusesHugeIterationCountBeforeDeriving` in `internal/smtpauth` used to
  assert that a refusal took under 100 ms, which fails on a loaded runner. It now
  counts the calls that reach the key derivation (0 for a refused iteration count,
  1 for an allowed one) with a test-only stub; no production code changed.
