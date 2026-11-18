- **INV-KDFMETER-zero-cost-when-off** With no observer installed (the production
  default), `GenerateFromPassword`/`CompareHashAndPassword` add exactly one atomic
  pointer load and a nil check over the wrapped bcrypt call, no allocation and no
  lock, and return byte-for-byte what bcrypt would. Routing production through the
  seam changes nothing observable. Guard: `TestKDFMeter_BehaviourIdenticalToBcrypt`
  and `TestKDFMeter_CountsGenerateAndCompare` (the observer-off half asserts the
  counters do not move).
