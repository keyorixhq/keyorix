- **INV-RES-airgap-fails-nonloopback** `NetMeter.DialContext` and the
  `NetMeter.Dialer()` Control hook RETURN AN ERROR (`*ErrAirGap`) for any dial to
  a non-loopback address unless `AllowNonLoopback` is set — they do not merely
  count it. This is the air-gap oracle: a fuzz target that reaches the real
  network instead of its hardened/fake client (ADR #1949, `refuseRedirect` /
  `connectGuardedDialer`) turns the input into a saved reproducer instead of
  silently dialing out or hanging on a real host. A non-loopback dial is also an
  unconditional `Budget.Check` failure regardless of any byte budget. "Loopback"
  means an IP that `net.IP.IsLoopback` accepts, or the literal `localhost`; a
  hostname needing DNS is treated as non-loopback so the oracle fires rather than
  resolving it. Why: the real defects this targets (SSRF, exfiltration, a
  retry-storm against a live endpoint) produce success at every return value —
  only the *attempted destination* distinguishes them, so the meter asserts on
  the dial, not on an error code the code under test may swallow. Guard:
  `TestAirGapBlocksNonLoopback` (red: `8.8.8.8:53` refused; green: a real
  `127.0.0.1` listener dialed and counted) in
  `internal/fuzzutil/resguard/resguard_test.go`.
