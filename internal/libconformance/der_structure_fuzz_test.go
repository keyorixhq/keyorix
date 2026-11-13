package libconformance

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/grammar"
)

// FuzzDERStructure is the standalone ASN.1-DER target this repository was missing
// (Phase 0 of the grammar campaign confirmed there is no other target whose
// property is over encoding/asn1 itself — it was previously exercised only
// incidentally inside internal/notary's token-builder fixture). It drives
// encoding/asn1.Unmarshal and crypto/x509.ParseCertificate / ParseCertificateRequest
// over GRAMMAR-BUILT DER: the fuzzer's bytes are decoded (grammar.DecodeDER) into
// a TLV tree plus a mutation set (indefinite length, non-minimal length, length
// overflow/under-run, wrong tag class, long-form tags, trailing bytes, deep
// nesting), and the tree is serialised to DER. The engine therefore mutates
// structural CHOICES, not raw octets, so its edits land past the first
// length/tag check instead of being rejected at octet 0.
//
// Oracles (all one-directional / self-consistent — none can false-positive):
//   - NEVER-PANIC: a panic in any of the three parsers propagates to the fuzzer
//     natively and is the finding.
//   - BOUNDED WORK: fuzzutil.Guard bounds wall-clock; a hang / super-linear
//     slowdown fails the target.
//   - BOUNDED ALLOCATION: TotalAlloc during the three parses must stay within a
//     generous envelope (64 MiB + 4 KiB·N), matching the sibling pkcs7 target —
//     catches an amplification regression by orders of magnitude while staying
//     far above any legitimate parse's footprint.
//   - MARSHAL/UNMARSHAL IDEMPOTENCE: if encoding/asn1 accepts the input as a
//     single RawValue with no trailing bytes, then marshalling that RawValue and
//     re-parsing it must succeed and yield the SAME (class, tag, isCompound,
//     bytes). This is "parse then marshal round-trip stable OR a clean error":
//     the clean-error side is the (common) case where asn1 rejects the mutated
//     input, which is never itself a failure here.
//
// What this oracle does NOT verify (stated explicitly, per the repo's
// machine-checked-over-asserted discipline):
//   - It does NOT assert that a semantically valid certificate / CSR / DER value
//     is ACCEPTED ("must parse"). A mutated input SHOULD be rejected far more
//     often than not, so only the reject-or-consistent direction is asserted.
//   - It does NOT assert that encoding/asn1 or crypto/x509 REJECT non-canonical
//     DER (non-minimal lengths, BER indefinite form, etc.). These libraries are
//     permitted to be lenient; asserting rejection would false-positive.
//   - It does NOT verify any trust / signature / chain property of a parsed
//     certificate — that is internal/notary's FuzzCertChainTrustInvariant.
//   - The idempotence check only covers the OUTERMOST TLV (asn1.RawValue does not
//     recurse), so a malformation buried inside a value that asn1 accepts
//     verbatim is not re-validated here.
func FuzzDERStructure(f *testing.F) {
	// Seeds are grammar-encoded control bytes (decoded by grammar.DecodeDER), not
	// raw DER — the whole point is that the engine mutates these choices.
	f.Add([]byte{0x00})                               // minimal random tree
	f.Add([]byte{0x01, 0x00, 0x20})                   // deep chain, modest depth
	f.Add([]byte{0x01, 0x10, 0x00})                   // deep chain, large depth (nesting lever)
	f.Add([]byte{0x02, 0x04, 0x00})                   // wide siblings
	f.Add([]byte{0x00, 0x30, 0x03, 0x02, 0x01, 0x01}) // random tree w/ content
	f.Add([]byte{0x00, 0x10, 0x11, 0x08})             // random tree w/ non-minimal-len mutation set

	f.Fuzz(func(t *testing.T, data []byte) {
		der := grammar.DecodeDER(data).Encode()

		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		var raw asn1.RawValue
		var rest []byte
		var uerr error
		fuzzutil.Guard(t.Fatalf, "asn1+x509 parse", func() {
			rest, uerr = asn1.Unmarshal(der, &raw)
			// Both x509 entry points over the same bytes — bounded-work / never-panic
			// only; results discarded.
			_, _ = x509.ParseCertificate(der)
			_, _ = x509.ParseCertificateRequest(der)
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(der))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: parsing a %d-byte DER value allocated %d bytes (limit %d) — amplification regression",
				len(der), alloc, limit)
		}

		// Marshal/unmarshal idempotence on the clean side.
		if uerr == nil && len(rest) == 0 {
			remar, merr := asn1.Marshal(raw)
			if merr != nil {
				// asn1 accepted it but cannot re-marshal its own RawValue — a genuine
				// library asymmetry.
				t.Fatalf("DER ROUND-TRIP: asn1.Unmarshal accepted a value asn1.Marshal then rejected: %v (der=%x)", merr, der)
			}
			var raw2 asn1.RawValue
			rest2, uerr2 := asn1.Unmarshal(remar, &raw2)
			if uerr2 != nil || len(rest2) != 0 {
				t.Fatalf("DER ROUND-TRIP: re-parsing a marshalled RawValue failed (err=%v restlen=%d)", uerr2, len(rest2))
			}
			if raw.Class != raw2.Class || raw.Tag != raw2.Tag || raw.IsCompound != raw2.IsCompound || !bytes.Equal(raw.Bytes, raw2.Bytes) {
				t.Fatalf("DER ROUND-TRIP: RawValue changed across marshal→unmarshal\n  before: class=%d tag=%d compound=%v bytes=%x\n  after:  class=%d tag=%d compound=%v bytes=%x",
					raw.Class, raw.Tag, raw.IsCompound, raw.Bytes, raw2.Class, raw2.Tag, raw2.IsCompound, raw2.Bytes)
			}
		}
	})
}
