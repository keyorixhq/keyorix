- **INV-KDFMETER-zero-cost-when-off** With no observer installed (the production
  default), `GenerateFromPassword`/`CompareHashAndPassword` add exactly one atomic
  pointer load and a nil check over the wrapped bcrypt call, no allocation and no
  lock, and return byte-for-byte what bcrypt would. Routing production through the
  seam changes nothing observable. Guard: `TestNotifyWithNoObserverAllocatesNothing`
  measures the per-call hook with `testing.AllocsPerRun` (calibrated by
  `TestAllocMeasureSeesSetObserverAllocation`, which must see the one allocation
  `SetObserver` makes); `TestKDFMeter_BehaviourIdenticalToBcrypt` and
  `TestKDFMeter_CountsGenerateAndCompare` cover the pass-through and the observer-off
  half (counters do not move). "No lock" is by inspection only: nothing measures it.
