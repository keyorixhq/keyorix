- **INV-KDFMETER-enablement-is-test-only** Installing an observer (`SetObserver`)
  is test-only; the sole legitimate caller is the resguard `KDFMeter`, a normal
  (non-`_test.go`) file kept test-only by `TestResguardImportedOnlyFromTests`. Guard:
  `TestKDFMeterSetObserver_NoProductionCallers` fails the build if any non-`_test.go`
  file references `SetObserver` — resolved through the file's own import of
  `internal/kdfmeter`, so an aliased import, a dot import, a method-value reference
  and a call from inside package `kdfmeter` are caught too — excluding by package path
  only `internal/fuzzutil/resguard`. `TestSetObserverGuard_Calibration` shows it red on
  each of those shapes and green on a comment/string mention. Does not see a reference
  built through reflection or `go:linkname`.
