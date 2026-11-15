- **INV-AUDITVERIFY-highwater-codec-roundtrip** The audit checkpoint high-water codec
  (`checkpoint.go`) is symmetric and fails closed. `EncodeHighWater`/`ParseHighWater`
  round-trip every carried field of a `Checkpoint`+signature (chained events, head id/hash,
  key version, seal count and digest, signature) byte-for-byte through the
  separator-joined `audit_checkpoint_highwater` layout. `ParseHighWater` treats any
  malformed value as "no mark" (ok=false, never a panic), and a value it accepts in the v2
  (sealed) layout always carries `Seals>=1` and a non-empty `SealDigest` — a malformed v2
  mark must never read as a sealed one and perturb `HighWaterOrder`'s rollback ranking. The
  codec is NOT an authenticator: the HMAC (`HighWaterSigMatches`) is checked separately, so
  a forged-but-well-formed value is still a correct parse. Why: the high-water mark is
  persisted to and read back from a DB text column for rollback protection; a parser that
  disagreed with its own encoder would decode a different snapshot than the one signed.
  Guard: `FuzzHighWaterRoundTrip`, `FuzzParseHighWater` (auditverify, I7 small-parser sweep).
