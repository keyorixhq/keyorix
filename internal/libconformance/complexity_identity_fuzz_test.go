package libconformance

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
	"github.com/keyorixhq/keyorix/internal/identity"
)

// FuzzIdentityNormalizeComplexity is a PerfFuzz-style cost-per-byte oracle over
// the golang.org/x/text PRECIS + NFC normalization that Keyorix applies to
// EVERY identity-bearing field (username, role, group, project, secret name)
// submitted over the wire. The live callers are internal/identity.NewFoldedName
// (precis.NewFreeform(LowerCase, Norm(NFC)) — internal/identity/identity.go:62)
// and NewAddressName (precis.OpaqueString — identity.go:103), reached from every
// authenticated HTTP/gRPC request carrying such a field. The upstream size limit
// is publicAuthBodyLimit = 64 KiB on /auth/* (server/http/body_limits.go:16);
// other authed routes fall under the 10 MiB global cap, but an identity field is
// never the whole body, so 64 KiB is a safe worst case for the per-field string.
//
// The property: normalizing an N-byte string must allocate work proportional to
// N, not to N². Unicode normalization (canonical decomposition + reordering +
// recomposition) is a classic place for super-linear blow-up on adversarial
// combining-mark sequences, and PRECIS adds bidi/class scans on top.
//
// What this oracle does NOT verify:
//   - It says nothing about the normalization RESULT — not that folding is
//     correct, not that two inputs that should fold equal do. Only cost.
//   - It does not prove 64 KiB is the true ceiling on a non-/auth route; it
//     proves the per-byte ratio, which is limit-independent, plus an absolute
//     ceiling derived from the 64 KiB auth limit.
//   - It measures allocated bytes (ReadMemStats), not CPU cycles; a parser that
//     is CPU-super-linear but allocation-linear would be caught only by the
//     coarse MaxWall sanity guard, not the byte ratio.
func FuzzIdentityNormalizeComplexity(f *testing.F) {
	f.Add("admin")
	f.Add("ADMIN role name")
	f.Add("café")                                 // precomposed vs decomposed
	f.Add("é́́́́")      // stacked combining marks
	f.Add(string(make([]byte, 0)))                // empty
	f.Add("ẛ̣")                         // NFC recomposition edge
	f.Add("Ạ̊̀́̂̃") // many reorderable marks

	// Budget: 64 KiB worst-case field, calibrated from TestComplexityBaselines.
	// Normalization output is a small multiple of input; a generous 512 B/byte
	// slope with a 2 MiB floor flags only genuine super-linear growth. Absolute
	// ceiling is the worst case at the 64 KiB auth limit (64 KiB·512 ≈ 32 MiB),
	// rounded to 64 MiB.
	budget := complexity.Budget{
		MaxAllocBytesPerByte: 512,
		FloorBytes:           2 << 20,
		AbsMaxAllocBytes:     64 << 20,
	}

	f.Fuzz(func(t *testing.T, raw string) {
		n := len(raw)
		c := complexity.Measure(func() {
			_, _ = identity.NewFoldedName(raw)
			_, _ = identity.NewAddressName(raw)
		})
		budget.Check(t.Fatalf, "identity.Normalize", n, c)
	})
}
