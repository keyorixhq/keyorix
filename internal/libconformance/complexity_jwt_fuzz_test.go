package libconformance

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// FuzzJWTParseComplexity is a cost-per-byte oracle over golang-jwt's structural
// decode (base64url of header+claims, then JSON unmarshal of each). Keyorix
// feeds this untrusted input: an OIDC id_token from the IdP is parsed at
// internal/oidcverify/oidc.go:186 (parser.ParseWithClaims) and
// internal/core/sso.go:1415, under the 10 MiB global request-body cap (gRPC
// MaxRecvMsgSize likewise 10 MiB).
//
// We call ParseUnverified, which performs exactly the attacker-reachable work
// that happens BEFORE any signature check: split on '.', base64url-decode the
// header and claims segments, and json.Unmarshal them. (The signature step
// needs a key and is not where an unauthenticated amplification would live —
// the decode happens first, on bytes the attacker fully controls.) The claims
// sink is jwt.MapClaims, the same map type the real verifier populates.
//
// Property: decoding an N-byte token must allocate O(N), not O(N²). A JSON body
// of deeply nested arrays/objects, or a base64 segment that decodes to a much
// larger structure, is the amplification shape.
//
// What this oracle does NOT verify:
//   - Nothing about validity: not signature, not alg, not exp/aud. Keyorix's
//     own alg-allowlist and claim checks are tested elsewhere
//     (FuzzJWTAlgorithmConfusion, FuzzVerifyIDTokenClaims). This is cost only.
//   - It does not model the keyfunc/signature verification cost (constant-ish,
//     and not attacker-amplifiable without a key).
//   - Allocated bytes, not CPU; a CPU-only blow-up is caught only by MaxWall.
func FuzzJWTParseComplexity(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")                 // minimal none-alg token
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIiwiYXVkIjoiYiJ9.AA") // typical shape
	f.Add("a.b.c")
	f.Add("...")
	f.Add("")

	parser := jwt.NewParser()

	// Budget calibrated in TestComplexityBaselines. base64 shrinks ~4:3; JSON
	// into a map allocates a few × the decoded bytes. 64 B/byte slope + 2 MiB
	// floor is generous. Absolute ceiling for a 10 MiB token: measured worst
	// case stays far under 256 MiB (see report).
	budget := complexity.Budget{
		MaxAllocBytesPerByte: 64,
		FloorBytes:           2 << 20,
		AbsMaxAllocBytes:     256 << 20,
	}

	f.Fuzz(func(t *testing.T, token string) {
		n := len(token)
		c := complexity.Measure(func() {
			var claims jwt.MapClaims
			_, _, _ = parser.ParseUnverified(token, &claims)
		})
		budget.Check(t.Fatalf, "jwt.ParseUnverified", n, c)
	})
}
