### Internal
- **Key-manager readers no longer wait on a KEK rotation's or DEK re-wrap's fsync.**
  `KeyManager`'s `RotateKEKPassphraseWithPrepare` (rotate-kek) and
  `RewrapDEKWithPrepare` (migrate-provider) used to hold the key manager's lock across
  their key-file writes and directory fsyncs, so `GetDEK`, `GetKeyVersion` and the
  KEK-derived key getters blocked for as long as the disk stalled. Both now
  serialise on their own lock and publish the new key state in one atomic step once
  the key files are durable; readers see the old state until then. On-disk format and
  crash-recovery behaviour are unchanged. Not changed: `RotateDEKWithSweep` still
  holds the lock across its re-encryption sweep, and `encryption.Service` still holds
  its own lock across a rotation or re-wrap it runs, so a secret encrypt or decrypt
  through the same `Service` still waits for it; a live server refuses both anyway
  (`dek.lock`) (#4376).
