# internal/kdfmeter — INVARIANTS

`kdfmeter` is the production-side seam for counting password-hash / key-derivation
(KDF) invocations. Production credential paths call its `GenerateFromPassword` /
`CompareHashAndPassword` instead of `golang.org/x/crypto/bcrypt` directly, so a
test harness (the resguard `KDFMeter`) can count bcrypt invocations deterministically
— the signal an account-enumeration timing oracle needs. See the package doc for
the full rationale.

- **INV-KDFMETER-zero-cost-when-off** With no observer installed (the production
  default), `GenerateFromPassword`/`CompareHashAndPassword` add exactly one atomic
  pointer load and a nil check over the wrapped bcrypt call, no allocation and no
  lock, and return byte-for-byte what bcrypt would. Routing production through the
  seam changes nothing observable. Guard: `TestKDFMeter_BehaviourIdenticalToBcrypt`
  and `TestKDFMeter_CountsGenerateAndCompare` (the observer-off half asserts the
  counters do not move).

- **INV-KDFMETER-enablement-is-test-only** Installing an observer (`SetObserver`)
  is test-only; the sole legitimate caller is the resguard `KDFMeter` from a
  test-only package. Guard: `TestKDFMeterSetObserver_NoProductionCallers` fails the
  build if any non-`_test.go` file calls `kdfmeter.SetObserver`, excluding by
  package path only the `internal/fuzzutil/resguard` helper (whose own test-only
  status is machine-enforced by `TestResguardImportedOnlyFromTests`).

- **INV-KDFMETER-counts-one-per-call** Each `GenerateFromPassword` notifies the
  observer exactly once with `OpGenerate`, each `CompareHashAndPassword` exactly
  once with `OpCompare`, before delegating. This one-to-one mapping is what lets the
  login-path balance invariant (`INV-CORE-login-kdf-cost-is-existence-balanced`) be
  asserted as an exact count. Guard: `TestKDFMeter_CountsGenerateAndCompare`.
