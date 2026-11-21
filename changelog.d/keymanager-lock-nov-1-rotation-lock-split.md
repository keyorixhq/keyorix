### Internal
- **Key-manager readers no longer wait on a KEK rotation's fsync.** `KeyManager`'s
  `RotateKEKPassphraseWithPrepare` used to hold the key manager's lock across its
  key-file writes and directory fsyncs, so `GetDEK`, `GetKeyVersion` and the
  KEK-derived key getters blocked for as long as the disk stalled. The rotation now
  serialises on its own lock and publishes the new keys in one atomic step once the
  key files are durable; readers see the old keys until then. On-disk format and
  crash-recovery behaviour are unchanged. Not changed: `RotateDEKWithSweep` still
  holds the lock across its re-encryption sweep, and `encryption.Service` still holds
  its own lock across a rotation it runs, so a secret encrypt or decrypt through the
  same `Service` still waits for the rotation; a live server refuses a rotation
  anyway (`dek.lock`) (#4376).
