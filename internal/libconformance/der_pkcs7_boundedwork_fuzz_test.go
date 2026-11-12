package libconformance

import (
	"runtime"
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/grammar"
)

// FuzzDERPKCS7BoundedWork is the GRAMMAR-DRIVEN counterpart to
// FuzzDigitorusPKCS7BoundedWork. It asserts the identical bounded-work property
// over the identical sink (digitorus/pkcs7's BER→DER parser — the one where the
// memory-amplification DoS and the OOB panic lived) but feeds it DER built from a
// grammar tree + mutation set (grammar.DecodeDER) instead of raw fuzzer bytes.
//
// The byte-level target mutates octets, so a single flipped length byte makes the
// whole structure unparseable and the engine stalls at the envelope. This target
// mutates STRUCTURAL CHOICES — deep nesting, indefinite length, non-minimal
// length, length overflow, long-form tags, wide sibling sets — so its edits reach
// the BER length/tag handling that the amplification bug lived in. The two
// targets are the DER half of the pre-registered grammar-vs-byte measurement
// (see /mnt/data/wave4/out/wg-REPORT.md Phase 2).
//
// Oracle (identical to the byte-level target, intentionally):
//   - fuzzutil.Guard bounds TIME (a hang / super-linear slowdown fails).
//   - the allocation check bounds MEMORY: TotalAlloc during Parse must stay within
//     64 MiB + 4 KiB·N of the built DER's size.
//
// What this does NOT verify: anything about the parse RESULT — not that a
// well-formed SignedData is accepted, not any signature/trust property. It
// asserts only the upper bound no correct linear-ish parser approaches. keyorix
// pins the fixed pkcs7, so this must pass today and only fires if a future bump
// reintroduces the amplification.
func FuzzDERPKCS7BoundedWork(f *testing.F) {
	f.Add([]byte{0x00})             // minimal random tree
	f.Add([]byte{0x01, 0x08, 0x00}) // deep nesting chain
	f.Add([]byte{0x02, 0x04, 0x00}) // wide siblings
	f.Add([]byte{0x00, 0x30, 0x11, 0x08, 0x20}) // random tree with length mutations
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		der := grammar.DecodeDER(data).Encode()

		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		fuzzutil.Guard(t.Fatalf, "pkcs7.Parse(grammar-DER)", func() {
			_, _ = pkcs7.Parse(der) // result discarded; time+memory are the property
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(der))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: pkcs7.Parse allocated %d bytes for a %d-byte grammar-built DER input (limit %d) — amplification regression",
				alloc, len(der), limit)
		}
	})
}
