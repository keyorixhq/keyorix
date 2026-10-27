- **INV-PQWRAP-wrap-key-binds-every-component** The envelope's wrap key is derived from BOTH
  shared secrets (ML-KEM first, then X25519) and a transcript hash over the header, BOTH KEM
  ciphertexts and BOTH recipient public keys; changing any one of these alone changes the wrap
  key. Version-1 known-answer vectors are frozen: a construction change is `Version = 2`, never
  an edit of the vectors. Why: pq-key-wrapping.md §4, Andrei's Q2 condition (2026-10-23).
  Guard: `TestDeriveWrapKey_BindsEveryComponent` (mutation-checked: dropping a ciphertext or a
  public key from the transcript fails it), `TestVectors`.
<!-- section: Envelope -->
