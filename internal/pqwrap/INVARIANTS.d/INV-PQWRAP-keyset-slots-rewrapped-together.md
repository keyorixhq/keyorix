- **INV-PQWRAP-keyset-slots-rewrapped-together** Keysets are written only by `SealKeyset`
  (every slot wrapped to one DEK under one header) and `RekeyKeyset` (KEK slot and MAC moved to
  a new KEK; header and every hybrid slot kept byte for byte, then the result is re-opened
  under the new KEK and compared). A DEK change therefore re-wraps every hybrid slot, to the
  public key stored in it and in the same order, in the same file; there is no writer that
  leaves one slot on an old DEK. Boot cannot detect a stale hybrid slot under a valid MAC (the
  server holds no escrow private key), which is why this has to hold for every writer. Why:
  pq-key-wrapping.md §7 "DEK rotation and the hybrid slots", §8. Guard (codec level):
  `TestSealKeyset_DEKRotationRewrapsEverySlot`, `TestRekeyKeyset_KeepsHybridSlotsByteForByte`,
  `TestSameRecipients`. The same rule at the `RotateDEKWithSweep` level (design tests 1-3) is
  UNGUARDED until the keyset is wired into internal/encryption (ask
  rd-pqwrap-2-encryption-scope).
<!-- section: Keyset -->
