- **INV-PQWRAP-keyset-slot-set-bound-to-header** The slot count is in the 22-byte header and the
  header is the KEK slot's AAD and every hybrid slot's envelope context. Dropping or adding a
  slot fails the boot before the MAC check (the count disagrees with the slots, or the KEK slot
  no longer opens), and an escrow holder's unwrap of a slot from the edited keyset fails too. A
  hybrid slot spliced in from an older keyset (old DEK, old KCV) never opens for its escrow
  holder. Why: pq-key-wrapping.md §7 (design test 5). Guard:
  `TestKeyset_DroppedSlotFailsBeforeMAC`, `TestKeyset_SlotFromOlderKeysetRefused`.
<!-- section: Keyset -->
