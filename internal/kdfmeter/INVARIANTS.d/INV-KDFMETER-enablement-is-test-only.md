- **INV-KDFMETER-enablement-is-test-only** Installing an observer (`SetObserver`)
  is test-only; the sole legitimate caller is the resguard `KDFMeter` from a
  test-only package. Guard: `TestKDFMeterSetObserver_NoProductionCallers` fails the
  build if any non-`_test.go` file calls `kdfmeter.SetObserver`, excluding by
  package path only the `internal/fuzzutil/resguard` helper (whose own test-only
  status is machine-enforced by `TestResguardImportedOnlyFromTests`).
