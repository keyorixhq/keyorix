package libconformance

// DIGITORUS/TIMESTAMP RFC 3161 (task XM1, oracles TS-1 / TS-2). digitorus/timestamp parses
// RFC 3161 Time-Stamp requests and responses. Keyorix's notary anchors audit checkpoints at a
// TSA: internal/notary/rfc3161.go builds a request with timestamp.CreateRequest and then feeds
// the TSA's REPLY to timestamp.ParseResponse (rfc3161.go:158) — attacker/TSA-controlled bytes
// — and internal/notary/notary.go calls timestamp.Parse on a stored token
// (notary.go:91, VerifyReceipt). Only digitorus/PKCS7 had a bounded-work fuzzer
// (FuzzDigitorusPKCS7BoundedWork); the timestamp layer that sits ON TOP of it (and does its
// own ASN.1 request/response decoding) was unfuzzed. This target closes that.
//
// ORACLE TS-1 — NO PANIC / BOUNDED WORK on the three parse entry points:
//   timestamp.ParseRequest, timestamp.Parse, timestamp.ParseResponse must, for ANY bytes,
//   return (value, error) without panicking and without doing work disproportionate to the
//   input. Time is bounded by fuzzutil.Guard; alloc/wall by a committed resguard budget. A
//   panic is recorded natively by the fuzzer; a hang/amplification fails with attribution.
//
// ORACLE TS-2 — REQUEST ROUND-TRIP IDEMPOTENCE:
//   for any bytes ParseRequest ACCEPTS, let req = ParseRequest(d); m = req.Marshal();
//   req2 = ParseRequest(m). Then req2.Marshal() == m — marshal∘parse is a fixed point. A
//   request whose re-serialisation is not stable means the "same" request has no single wire
//   form; that is a round-trip defect in the request codec.
//
// REACHABILITY (honest):
//   - ParseResponse and Parse ARE reachable on hostile input (the TSA reply / a stored token).
//     BUT the production path at rfc3161.go wraps ParseResponse in a recover() AND gates it
//     behind validateDERFraming(body) (strict-DER framing), which rejects the BER-amplification
//     class before the library sees it. So a TS-1 amplification finding against ParseResponse
//     is reachable at the LIBRARY but mitigated in-repo by the derframing guard — it would be
//     reported upstream-style (HARDENING), labelled "not reachable through the live guard",
//     unless it bypasses strict-DER framing. A PANIC in ParseResponse/Parse that the repo's
//     recover() does NOT also stop would be a genuine reachable DoS.
//   - ParseRequest is NOT reached on attacker input (Keyorix only CreateRequests; it never
//     parses a request from a third party). TS-2 is therefore LIBRARY CONFORMANCE, not a
//     reachable Keyorix property; stated so the result is not over-read.
//
// WHAT THIS ORACLE DOES NOT VERIFY:
//   - It does NOT verify the TSA signature, the PKI status semantics, or that a parsed
//     Timestamp's Time/SerialNumber are correct — only that parsing is panic-free, bounded, and
//     (for requests) round-trip-stable. Signature/chain validation is notary.go's own concern.
//   - Parse/ParseResponse round-trip is NOT asserted: re-emitting a signed response needs a
//     TSA key (CreateResponse), which is out of scope for a pure-parser target.
//   - The resource meter sees only this process's alloc/wall; the production cgroup memory cap
//     and validateDERFraming are the backstops it does not model.

import (
	"bytes"
	"crypto"
	"math/big"
	"testing"

	"github.com/digitorus/timestamp"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const digitorusTimestampBudgetPath = "testdata/resguard-digitorus-timestamp.json"

// validRequestSeeds builds a handful of well-formed RFC 3161 requests with timestamp's own
// CreateRequest, so the round-trip oracle (TS-2) has accepted inputs to exercise and the
// corpus is not purely rejections.
func validRequestSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	var out [][]byte
	cases := []*timestamp.RequestOptions{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, Certificates: true},
		{Hash: crypto.SHA512, Nonce: big.NewInt(0x1234567890abcdef)},
		{Hash: crypto.SHA1},
	}
	for _, opts := range cases {
		der, err := timestamp.CreateRequest(bytes.NewReader([]byte("keyorix-audit-checkpoint")), opts)
		if err != nil {
			continue
		}
		out = append(out, der)
	}
	return out
}

// FuzzDigitorusTimestamp is oracles TS-1 and TS-2. See the file header.
func FuzzDigitorusTimestamp(f *testing.F) {
	for _, s := range validRequestSeeds(f) {
		f.Add(s)
	}
	// Hostile ASN.1 shapes: indefinite-length BER, a huge-OID-ish prefix, deep nesting, empty.
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})                                           // SEQUENCE, indefinite length, EOC
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})                                     // minimal DER SEQUENCE
	f.Add(bytes.Repeat([]byte{0x30, 0x80}, 64))                                     // deeply nested indefinite SEQUENCEs
	f.Add([]byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}) // an OID
	f.Add([]byte{})

	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	budget, err := resguard.LoadBudget(digitorusTimestampBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardDigitorusTimestampCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", digitorusTimestampBudgetPath)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 { // a parser hang on a bigger input is a different scope
			return
		}

		// TS-1: ParseResponse — the live hostile sink.
		cost := probe.Measure(len(data), func() {
			fuzzutil.Guard(t.Fatalf, "timestamp.ParseResponse", func() {
				_, _ = timestamp.ParseResponse(data)
			})
		})
		resguard.FeedCoverage(cost)
		if haveBudget {
			budget.Check(t.Fatalf, cost)
		}

		// TS-1: Parse — the stored-token sink (VerifyReceipt).
		fuzzutil.Guard(t.Fatalf, "timestamp.Parse", func() {
			_, _ = timestamp.Parse(data)
		})

		// TS-1 + TS-2: ParseRequest — library conformance (not a hostile sink) + round-trip.
		fuzzutil.Guard(t.Fatalf, "timestamp.ParseRequest", func() {
			finding, _ := requestRoundTrip(data, (*timestamp.Request).Marshal)
			if finding != "" {
				t.Fatalf("%s\n input=%q", finding, data)
			}
		})
	})
}

// requestRoundTrip is the TS-2 oracle body, parameterised by the marshal function so the
// red/green proof can inject a non-idempotent marshaller (the real library's own Marshal has
// no seam to break). It returns a non-empty finding when marshal∘parse is NOT a fixed point
// for an input ParseRequest accepts, and exercised=true when the round-trip actually ran (an
// input ParseRequest rejects, or a request that cannot be marshalled at all, is a safe
// skip — exercised=false, no finding).
func requestRoundTrip(data []byte, marshal func(*timestamp.Request) ([]byte, error)) (finding string, exercised bool) {
	req, err := timestamp.ParseRequest(data)
	if err != nil || req == nil {
		return "", false // rejected: nothing to round-trip
	}
	m1, err := marshal(req)
	if err != nil {
		return "", false // parses but cannot re-marshal: not asserted here (see report)
	}
	req2, err := timestamp.ParseRequest(m1)
	if err != nil || req2 == nil {
		return "TS-2 ROUND-TRIP: request re-marshal is not re-parseable", true
	}
	m2, err := marshal(req2)
	if err != nil {
		return "TS-2 ROUND-TRIP: re-marshal of a re-parsed request failed", true
	}
	if !bytes.Equal(m1, m2) {
		return "TS-2 ROUND-TRIP: marshal∘parse is not a fixed point", true
	}
	return "", true
}
