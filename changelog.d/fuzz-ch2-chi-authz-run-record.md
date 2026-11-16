### Testing
- **CH2 run: the CH1 fuzzer was exercised for 126 minutes of real wall time**
  (14×540s chunks, ~23M executions, `-parallel 2`) against the real middleware, table
  and chi router. Zero oracle violations (no CH1-A bypass, CH1-B wrong-route refusal or
  new CH1-C routing-differential class); the interesting-input corpus saturated at ~213
  entries. No crasher, no harness bug, and no production change: the latent decoded-path
  fallback branch flagged in CH1 stayed unreachable under every fuzzed input, so the
  optional hardening was deliberately NOT applied.
