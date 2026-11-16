- **INV-FUZZCLOUD-bcrypt-roundtrip-failclosed** `golang.org/x/crypto/bcrypt` as
  `internal/core` uses it round-trips and fails closed: a hash from
  `GenerateFromPassword(pw, MinCost)` verifies `pw` (`CompareHashAndPassword`
  returns nil) and REJECTS any different password (returns non-nil); and
  `CompareHashAndPassword` on an arbitrary hostile hash never panics. Hostile
  hashes whose *declared cost* is large are bounded out before the compare —
  bcrypt genuinely runs 2^cost rounds, so a cost=31 stored hash is a CPU bomb;
  this is recorded as a documented property, not fuzzed into a hang. Does NOT
  test the constant-time/timing property, the dummy-hash equal-time path, or
  cost>MinCost round-trips. Why: reachgen ranks `CompareHashAndPassword` #8 in
  `scripts/fuzzing/reachgen/RANKED-TOP40.md` (9 untrusted request-body sites,
  every login), with no prior dedicated fuzz target. Guard: `FuzzBcryptRoundTripHostileHash`
  (`fuzz/thirdparty/bcrypt/bcrypt_roundtrip_fuzz_test.go`), red-proofed by
  corrupting the hash before verify.
