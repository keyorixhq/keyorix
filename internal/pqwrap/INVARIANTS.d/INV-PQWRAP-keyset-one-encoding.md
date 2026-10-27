- **INV-PQWRAP-keyset-one-encoding** A keyset has exactly one encoding and the parser refuses
  everything else before any cryptography: slot 0 is the only KEK slot (76 bytes), every later
  slot is a hybrid slot whose length is fixed by its suite, its stored public key parses, its
  envelope has purpose DEK with the same suite and key id as that key, no recipient repeats, and
  no byte follows the MAC. A key file is detected as legacy-60 (exactly 60 bytes), keyset-v1, or
  unknown, and unknown is refused, never guessed; a keyset of a newer version is refused with
  `ErrKeysetVersion`. Why: pq-key-wrapping.md §5, §7, §12. Guard:
  `TestKeyset_HybridSlotStructureCheckedAtBoot`, `TestKeyset_TruncationAndTrailingRefused`,
  `TestDetectFormat`, `TestOpenKeyFile_UnknownFormatRefused`,
  `TestKeyset_NewerVersionFailsClosedWithClearError`, `FuzzOpenKeyFile`.
<!-- section: Keyset -->
