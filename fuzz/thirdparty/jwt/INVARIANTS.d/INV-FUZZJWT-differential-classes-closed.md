- **INV-FUZZJWT-differential-classes-closed** Every disagreement between golang-jwt's
  structural parse (`ParseUnverified` with Keyorix's asymmetric-only `WithValidMethods`)
  and the in-harness strict RFC 7519/7515/8725 reference decoder, on the same bytes, is a
  NAMED class in `EXPECTED-DIFFERENCE.md` (base64 non-canonical, duplicate JSON member
  names, and the structural-vs-verification leniencies of `ParseUnverified`). A NEW,
  unclassified disagreement — in either direction — fails the fuzzer; the EXPECTED-DIFFERENCE
  table is the committed allowlist. Why: no second JWT implementation is in the offline
  module cache, so the strict reference decoder is the differential oracle; the table keeps
  it honest. Guard: `FuzzJWTDifferential` (`fuzz/thirdparty/jwt`) plus the committed
  `EXPECTED-DIFFERENCE.md`.
