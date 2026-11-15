package auditverify

// FuzzParseSeals feeds arbitrary bytes to ParseSeals — the parser of the
// system_metadata "audit_seals" value (seal.go), the record of accepted audit
// losses (`admin audit accept-loss`). A value read back from a text column an
// operator with database write access, or a corrupted store, can set to
// anything. ParseSeals MACs are not checked here (that is loadSeals' job); this
// target drives the structural parse.
//
// ORACLE: two parts.
//  1. Never panics on any input (base64 decode, JSON unmarshal, shape and
//     link-chain checks must all fail closed with errSealMalformed, never
//     crash).
//  2. Structural invariant on success — a record set ParseSeals ACCEPTS must be
//     a well-linked chain: Seq is 1-based and consecutive (recs[i].Seq==i+1),
//     the first record's Prev is empty, and every later record's Prev equals
//     the previous record's Digest(). ParseSeals is the only gate before these
//     records drive gap/truncation acceptance (sealsCover, checkSealEvents); a
//     mis-linked set reading as valid would let one acceptance's digest chain
//     to another's.
//
// WHAT THIS DOES NOT VERIFY:
//   - No MAC authentication (MACValid): an accepted set is parsed, not trusted.
//   - It does not assert byte-identity with internal/core.parseAuditSeals
//     (unexported).
//   - It does not check the semantic gap/truncation coverage rules
//     (sealAnchorCovers etc.), only the parse-time shape and linkage.
import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// buildSealLine encodes one record the way core's accept-loss writer does:
// aseal-v1 \x1f base64(payload) \x1f kid \x1f mac, with payload the JSON of the
// record. The MAC is a placeholder — ParseSeals does not check it.
func buildSealLine(tb testing.TB, s *Seal, prevDigestHex string) (line string, digestHex string) {
	tb.Helper()
	s.V = 1
	s.Prev = prevDigestHex
	payload, err := json.Marshal(s)
	if err != nil {
		tb.Fatalf("marshal seal: %v", err)
	}
	sum := sha256.Sum256(payload)
	return strings.Join([]string{
		"aseal-v1",
		base64.RawURLEncoding.EncodeToString(payload),
		"kv1",
		"0011deadbeef",
	}, "\x1f"), hex.EncodeToString(sum[:])
}

func FuzzParseSeals(f *testing.F) {
	// A valid single record (one accepted gap).
	one := &Seal{Seq: 1, Gaps: []SealGap{{LastGoodID: 5, LastGoodHash: "h5", ResumeID: 9, ResumeHash: "h9"}}}
	line1, dig1 := buildSealLine(f, one, "")
	f.Add(line1)

	// A valid two-record chain: record 2's Prev is record 1's digest.
	two := &Seal{Seq: 2, Gaps: []SealGap{{LastGoodID: 20, LastGoodHash: "h20", ResumeID: 25, ResumeHash: "h25"}}}
	line2, _ := buildSealLine(f, two, dig1)
	f.Add(line1 + "\n" + line2)

	// A truncation-only record (the other valid shape).
	trunc := &Seal{Seq: 1, Truncation: &SealTruncation{CertifiedHeadID: 100, CertifiedHeadHash: "hc", SurvivingHeadID: 90}}
	tline, _ := buildSealLine(f, trunc, "")
	f.Add(tline)

	// Malformed seeds.
	f.Add("")
	f.Add("aseal-v1\x1fnotbase64\x1fkv\x1fmac")
	f.Add("wrong-domain\x1fAA\x1fkv\x1fmac")
	f.Add("aseal-v1\x1f\x1f\x1f") // empty fields

	f.Fuzz(func(t *testing.T, val string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseSeals panicked on %q: %v", val, r)
			}
		}()

		recs, err := ParseSeals(val)
		if err != nil {
			return // malformed → errSealMalformed, the safe outcome
		}
		// Accepted: the records must form a well-linked, consecutively-sequenced
		// chain. (ParseSeals returns a nil, zero-length slice for the empty
		// string split edge only when a line is malformed — a success always
		// means every line parsed.)
		for i, r := range recs {
			if r.Seq != i+1 {
				t.Fatalf("ParseSeals accepted record #%d with Seq=%d (want %d) from %q", i, r.Seq, i+1, val)
			}
			if i == 0 {
				if r.Prev != "" {
					t.Fatalf("ParseSeals accepted a first record with non-empty Prev=%q from %q", r.Prev, val)
				}
				continue
			}
			if want := recs[i-1].Digest(); r.Prev != want {
				t.Fatalf("ParseSeals accepted record #%d whose Prev=%q != previous Digest=%q from %q", i, r.Prev, want, val)
			}
		}
	})
}
