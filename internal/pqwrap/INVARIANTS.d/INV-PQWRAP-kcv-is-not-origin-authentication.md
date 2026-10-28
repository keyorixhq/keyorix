- **INV-PQWRAP-kcv-is-not-origin-authentication** Pinned non-property: anyone holding a
  recipient public key can make a valid envelope, and without the KEK nothing in a keyset
  authenticates its writer. The header KCV only catches a slot that disagrees with its header;
  an attacker who rewrites the KCV and the hybrid slot together gets the escrow holder to open
  the attacker's DEK. An archive-only escrow restore therefore needs archive origin
  authentication (open decision Q10) and a mandatory DEK rotation afterwards, and is not offered
  until Q10 is decided. If a guard below starts failing, correct §6 of the design note; do not
  delete the test. Why: pq-key-wrapping.md §6. Guard:
  `TestKeyset_KCVIsNotOriginAuthentication`,
  `TestWrap_AnyPublicKeyHolderCanWrap_NoOriginAuthentication`.
<!-- section: Keyset -->
