- **INV-PQWRAP-closed-suite-registry** The reader accepts exactly the compiled-in suites
  (`0x0001` X25519 + ML-KEM-768, `0x0002` X25519 + ML-KEM-1024); every one has an ML-KEM
  component, so no classical-only wrap can be expressed. No configuration, flag or peer chooses
  a suite: the DEK envelope policy is `0x0001` and keyset recipients are written only with
  `RecipientSuite` (`0x0002`). A new algorithm is a new suite id in a reviewed change with its
  own vectors. Why: pq-key-wrapping.md §5 "No runtime algorithm switch", Q1/Q3. Guard:
  `TestSuiteRegistry_ClosedAndNeverClassicalOnly`, `TestUnwrap_SuiteConfusionFails`,
  `TestSealKeyset_RefusesBadInput` (an ML-KEM-768 recipient is refused).
<!-- section: Envelope -->
