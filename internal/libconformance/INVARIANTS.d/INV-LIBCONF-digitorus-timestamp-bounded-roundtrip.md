- **INV-LIBCONF-digitorus-timestamp-bounded-roundtrip** `github.com/digitorus/timestamp`'s three
  parse entry points — `ParseRequest`, `Parse`, `ParseResponse` — must, for ANY bytes, return
  `(value, error)` without panicking and within a committed resguard alloc/wall budget (no work
  disproportionate to input); and for any request `ParseRequest` accepts, `marshal∘parse` must be
  a fixed point (`req.Marshal()` re-parses and re-marshals to identical bytes). Why: Keyorix's
  notary anchors audit checkpoints at an RFC 3161 TSA — `internal/notary/rfc3161.go:158` feeds the
  TSA's reply to `timestamp.ParseResponse` (attacker/TSA-controlled) and `internal/notary/notary.go:91`
  calls `timestamp.Parse` on a stored token. Only digitorus/PKCS7 had a bounded-work fuzzer; the
  timestamp layer on top of it (with its own ASN.1 request/response decoding) was unfuzzed.
  Reachability is honest: the production ParseResponse path is guarded by strict-DER framing +
  `recover()`, so a BER-amplification finding is upstream/HARDENING (not reachable through the live
  guard), while an unrecovered panic would be a reachable DoS; `ParseRequest` is NOT reached on
  attacker input (Keyorix only CreateRequests), so TS-2 is library conformance. Guard:
  `FuzzDigitorusTimestamp` with `TestDigitorusTimestampRoundTripRedGreen` and
  `TestResguardDigitorusTimestampBudgetRedGreen` (`internal/libconformance`,
  `digitorus_timestamp_fuzz_test.go` + `_redproof_test.go`).
