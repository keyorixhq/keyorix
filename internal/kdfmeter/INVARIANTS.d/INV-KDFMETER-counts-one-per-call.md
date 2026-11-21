- **INV-KDFMETER-counts-one-per-call** Each `GenerateFromPassword` notifies the
  observer exactly once with `OpGenerate`, each `CompareHashAndPassword` exactly
  once with `OpCompare`, before delegating. This one-to-one mapping is what lets the
  login-path balance invariant (`INV-CORE-login-kdf-cost-is-existence-balanced`) be
  asserted as an exact count. Guard: `TestKDFMeter_CountsGenerateAndCompare`.
