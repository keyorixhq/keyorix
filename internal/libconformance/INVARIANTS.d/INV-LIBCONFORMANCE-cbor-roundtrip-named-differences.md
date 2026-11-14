- **INV-LIBCONFORMANCE-cbor-roundtrip-named-differences** fxamacker/cbor/v2
  value-level re-encode is idempotent: for any input the default DecMode accepts,
  `v1 := decode(data); b := encode(v1); v2 := decode(b)` yields `v2` equal to `v1`
  under numeric/NaN-aware comparison. Every way the two can legitimately disagree is a
  NAMED class in the committed EXPECTED-DIFFERENCE table (`EXPECTED-DIFFERENCE.md`):
  NaN≠NaN under `reflect.DeepEqual`, bignum↔int64/uint64 re-typing, and the first
  decode's normalization of indefinite-length / duplicate-map-key / non-canonical
  integer encodings. ONLY a new, unnamed disagreement class fails the target — that is
  the "one bug class, many libraries" slide. The property is stated on `v1↔v2`, NOT
  `data↔v1`: CBOR has many encodings per value and Keyorix never relies on byte-exact
  CBOR round-trip, so `data↔v1` fidelity is deliberately out of scope. Why: the
  round-trip bug class from the pkcs7/binary campaign, transferred to CBOR; a future
  codec bump that silently dropped or re-typed a value would surface here. Red/green
  proof: the equality oracle rejects `1 == 2` and accepts `int64(5) == uint64(5)`.
  Guard: `FuzzCBORRoundTrip` (`internal/libconformance`).
