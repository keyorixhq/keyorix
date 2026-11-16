- **INV-FUZZUUID-parse-roundtrip** For any string `s` that `uuid.Parse` accepts,
  `uuid.Parse(u.String())` yields the SAME 16 bytes, and `u.String()` is itself strictly
  canonical (`^[0-9a-fA-F]{8}-…-[0-9a-fA-F]{12}$`). Additionally every string the strict
  canonical regex accepts, `uuid.Parse` MUST accept (uuid is a documented superset). Why:
  a verifier compares the bytes a parsed uuid yields; the library's own serialisation must
  re-parse to the same value, and a canonical uuid must never be rejected. **Does NOT
  verify**: that `uuid.Parse` REJECTS non-canonical forms — accepting raw-hex / urn /
  `{brace}` forms is intended leniency (uuid's own doc: "Parse should not be used to
  validate strings"); no differential against a second uuid implementation (one-way vs a
  regex only). Guard: `FuzzUUIDParse` (`fuzz/thirdparty/uuid`).
- **INV-FUZZUUID-frombytes-roundtrip** `uuid.FromBytes(b)` errors iff `len(b) != 16`, and on
  a 16-byte slice round-trips through `String()`→`Parse` to the same value, with no panic on
  any length. Why: this is the ACTUALLY-reachable path (AAGUID = 16 raw attestation bytes via
  go-webauthn). **Does NOT verify**: anything about the string parser (that is
  `FuzzUUIDParse`); the semantic meaning of the AAGUID. Guard: `FuzzUUIDFromBytes`,
  `TestFromBytesRoundTrip` (`fuzz/thirdparty/uuid`).
