- **INV-FUZZUUID-frombytes-roundtrip** `uuid.FromBytes(b)` errors iff `len(b) != 16`, and on
  a 16-byte slice round-trips through `String()`→`Parse` to the same value, with no panic on
  any length. Why: this is the ACTUALLY-reachable path (AAGUID = 16 raw attestation bytes via
  go-webauthn). **Does NOT verify**: anything about the string parser (that is
  `FuzzUUIDParse`); the semantic meaning of the AAGUID. Guard: `FuzzUUIDFromBytes`,
  `TestFromBytesRoundTrip` (`fuzz/thirdparty/uuid`).
