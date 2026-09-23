package libconformance

import (
	"runtime"
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzDigitorusPKCS7BoundedWork is a bounded-work invariant fuzzer for digitorus/pkcs7's
// BER→DER parser — the exact code where we found and disclosed the memory-amplification DoS
// (CVE-2026-45447) and the OOB-panic, both reachable via keyorix's RFC3161/notary path. The
// never-panic harness sailed past the DoS because it was slowness, not a crash. This turns it
// into a sub-hang amplification detector: parsing an N-byte input must not do work
// disproportionate to N.
//
//   - fuzzutil.Guard bounds TIME (a hang / super-linear slowdown fails the target).
//   - the allocation check bounds MEMORY: TotalAlloc during Parse must stay within a generous
//     envelope (64 MiB + 4 KiB·N). The disclosed amplification turned ~130 bytes into ~1.8 GB,
//     so this floor catches a regression by three orders of magnitude while staying far above
//     any legitimate parse's footprint (no false positives from GC/fuzzer noise, which is
//     KiB–MiB scale). keyorix pins the fixed pkcs7, so this must pass today and only fires if a
//     future bump reintroduces the amplification.
//
// Sound: it asserts only an upper bound no correct linear-ish parser approaches.
func FuzzDigitorusPKCS7BoundedWork(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) // minimal DER SEQUENCE
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))    // BER-ish prefix
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		fuzzutil.Guard(t.Fatalf, "pkcs7.Parse", func() {
			_, _ = pkcs7.Parse(data) // result discarded; time+memory are the property
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(data))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: pkcs7.Parse allocated %d bytes for a %d-byte input (limit %d) — amplification regression",
				alloc, len(data), limit)
		}
	})
}
