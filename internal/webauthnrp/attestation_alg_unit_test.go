package webauthnrp

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// TestCheckStatementKeyAlg_AndroidKey covers the one format the end-to-end test
// cannot reach: an android-key x5c must chain to Google's hardware roots before
// the library returns, so no fixture registers. The library verifies the
// statement signature with x509 CheckSignature (curve-blind) and again with the
// credential key's own alg, so -47 over a P-256 certificate and credential key
// passes it; checkStatementKeyAlg refuses it, and the genuine ES256/P-256 shape
// passes. A missing alg or x5c fails closed.
func TestCheckStatementKeyAlg_AndroidKey(t *testing.T) {
	cert := attCertFor(t, tpmDetKey(t, "android attestation"))
	x5c := []any{cert}
	for _, tc := range []struct {
		name string
		stmt map[string]any
		ok   bool
	}{
		{"ES256 with a P-256 cert", map[string]any{"alg": int64(-7), "x5c": x5c}, true},
		{"ESP256 with a P-256 cert", map[string]any{"alg": int64(-9), "x5c": x5c}, true},
		{"ES256K (-47) with a P-256 cert", map[string]any{"alg": algES256K, "x5c": x5c}, false},
		{"ES384 with a P-256 cert", map[string]any{"alg": int64(-35), "x5c": x5c}, false},
		{"RS256 with a P-256 cert", map[string]any{"alg": int64(-257), "x5c": x5c}, false},
		{"no alg", map[string]any{"x5c": x5c}, false},
		{"no x5c", map[string]any{"alg": int64(-7)}, false},
		{"x5c entry not bytes", map[string]any{"alg": int64(-7), "x5c": []any{"cert"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStatementKeyAlg(string(protocol.AttestationFormatAndroidKey), tc.stmt)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			requireAttFormatRefusal(t, tc.name, err)
		})
	}
}

// TestCheckStatementKeyAlg_FormatsWithoutABinding: fido-u2f and apple (no alg),
// packed self attestation (no x5c; the library binds alg to the credential key)
// and none are left to the library.
func TestCheckStatementKeyAlg_FormatsWithoutABinding(t *testing.T) {
	for _, tc := range []struct {
		format string
		stmt   map[string]any
	}{
		{"fido-u2f", map[string]any{"x5c": []any{[]byte("not parsed")}}},
		{"apple", map[string]any{"x5c": []any{[]byte("not parsed")}}},
		{"packed", map[string]any{"alg": int64(-7), "sig": []byte{1}}},
		{"none", map[string]any{}},
	} {
		if err := checkStatementKeyAlg(tc.format, tc.stmt); err != nil {
			t.Errorf("%s: refused: %v", tc.format, err)
		}
	}
}
