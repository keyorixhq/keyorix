- **INV-PQWRAP-keyset-dek-rotation-rewraps-every-slot** A DEK rotation through
  `RotateDEKWithSweep` (`internal/encryption`) re-wraps every hybrid slot of the keyset to the
  new DEK in the same `OpRotateDEK` commit, keeping the recipient key ids and slot order; it
  refuses to run (no `dek.key.pending`, no row re-encrypted, `dek.key` unchanged) when a slot
  cannot be re-wrapped; and a crash at any step leaves either the old keyset with every slot on
  the old DEK or the new keyset with every slot on the new DEK, never a mix. Boot cannot detect
  a stale hybrid slot under a valid MAC, so the rotation path has to keep this itself. Why:
  pq-key-wrapping.md §7 "DEK rotation and the hybrid slots" and its design tests 1-3.
  UNGUARDED (#3758): the keyset is not wired into internal/encryption yet; the codec-level
  half is `INV-PQWRAP-keyset-slots-rewrapped-together`.
<!-- section: Keyset -->
