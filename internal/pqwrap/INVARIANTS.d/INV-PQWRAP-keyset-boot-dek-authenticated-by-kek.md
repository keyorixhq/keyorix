- **INV-PQWRAP-keyset-boot-dek-authenticated-by-kek** `OpenKeyset` (and `OpenKeyFile` for a
  keyset) returns a DEK only when, in this order, the KEK slot opens under the KEK with
  AAD = header ‖ slot index, the keyset MAC (HMAC-SHA256 under HKDF(KEK,
  `keyorix/pqwrap/v1/keyset-mac`)) verifies over header ‖ slots, and the DEK matches the
  header's KCV. This closes the KEM-DEM DEK-substitution gap: a key-directory writer who holds
  only recipient public keys can build a valid envelope around a DEK of their choice, but not a
  keyset the server boots from. Why: pq-key-wrapping.md §6, §7. Guard:
  `TestKeyset_DEKSubstitutionRefused` (mutation-checked: removing the MAC comparison fails it,
  `TestKeyset_SlotFromOlderKeysetRefused` and `TestKeyset_EveryByteFlipFails`),
  `TestKeyset_WrongKEKRefused`, `FuzzOpenKeyFile` (a successful open only ever yields the one
  DEK sealed under the fuzz KEK).
<!-- section: Keyset -->
