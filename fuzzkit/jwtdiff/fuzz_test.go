package jwtdiff

import (
	"context"
	"testing"
)

// FuzzJWTVerifyDifferential drives the golang-jwt-vs-stdlib-reference JWT
// verification oracle. The fuzzer's bytes become token "knobs" (header alg,
// signing key, claim shapes); the same token and pinned config go to both
// verifiers; any accept/reject or subject disagreement the documented-differences
// table does not explain is reported.
//
// A divergence here is a lead to triage by hand (RFC 7515/7519, then decide which
// side is right), not a committed crasher — reproducer bytes for any finding in a
// third-party library stay private (.scratch/findings/, per
// scripts/fuzzing/DISCLOSURE-TRIAGE.md). The printed knobs reconstruct the case.
func FuzzJWTVerifyDifferential(f *testing.F) {
	c := NewComparator()

	seeds := [][]byte{
		{0, 0},                      // genuine RS256
		{1, 1},                      // genuine ES256
		{2, 2},                      // genuine HS256
		{0, 3},                      // alg none vs RS256 pin
		{0, 2, 0, 1},                // RS/HS confusion (HS256 signed with RSA pub)
		{0, 0, 1},                   // wrong RS key
		{0, 0, 0, 0, 1},             // expired
		{0, 0, 0, 0, 2},             // missing exp
		{0, 0, 0, 0, 0, 2},          // nbf future
		{0, 0, 0, 0, 0, 0, 2},       // aud wrong
		{0, 0, 0, 0, 0, 0, 3},       // aud missing
		{0, 0, 0, 0, 0, 0, 1},       // aud in array
		{0, 0, 0, 0, 0, 0, 0, 1},    // tampered signature
		{2, 2, 0, 0, 0, 0, 0, 0, 1}, // HS256 genuine with kid
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		k := decodeKnobs(data)
		diverged, d := c.Compare(context.Background(), inputFor(k))
		if diverged {
			t.Errorf("JWT VERIFY DIVERGENCE knobs=%+v\n%v", k, d)
		}
	})
}
