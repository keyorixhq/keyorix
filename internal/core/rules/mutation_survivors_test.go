package rules

// MUTANT-SEC-3: boundary and effect assertions for mutants of the rules leaf
// package that the existing example and fuzz tests left alive.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// bigWithBits returns an integer whose bit length is exactly bits.
func bigWithBits(bits int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) }

func rsaJWK(bits int, e []byte) JWK {
	return JWK{Kty: "RSA", N: b64u(bigWithBits(bits).Bytes()), E: b64u(e)}
}

func TestParseJWK_RSAModulusBoundsAreExact(t *testing.T) {
	e65537 := big.NewInt(65537).Bytes()
	for _, tc := range []struct {
		bits int
		ok   bool
	}{
		{MinRSABits - 1, false}, {MinRSABits, true}, {MinRSABits + 1, true},
		{MaxRSABits - 1, true}, {MaxRSABits, true}, {MaxRSABits + 1, false},
	} {
		key, err := ParseJWK(rsaJWK(tc.bits, e65537))
		if tc.ok {
			require.NoError(t, err, "%d bits", tc.bits)
			assert.Equal(t, tc.bits, key.(*rsa.PublicKey).N.BitLen(), "%d bits", tc.bits)
			continue
		}
		require.Error(t, err, "%d bits", tc.bits)
		assert.Contains(t, err.Error(), "outside allowed range")
	}
}

func TestParseJWK_RSAExponentBoundsAreExact(t *testing.T) {
	exp := func(v *big.Int) []byte { return v.Bytes() }

	_, err := ParseJWK(rsaJWK(MinRSABits, nil))
	require.Error(t, err, "e = 0")
	assert.Contains(t, err.Error(), "out of range")

	_, err = ParseJWK(rsaJWK(MinRSABits, []byte{0}))
	require.Error(t, err, "e = 0 (one zero byte)")
	assert.Contains(t, err.Error(), "out of range")

	one, err := ParseJWK(rsaJWK(MinRSABits, exp(big.NewInt(1))))
	require.NoError(t, err, "e = 1 is positive and in range here")
	assert.Equal(t, 1, one.(*rsa.PublicKey).E)

	huge := new(big.Int).Lsh(big.NewInt(1), 70)
	_, err = ParseJWK(rsaJWK(MinRSABits, exp(huge)))
	require.Error(t, err, "e beyond int64")
	assert.Contains(t, err.Error(), "out of range")

	_, err = ParseJWK(rsaJWK(MinRSABits, exp(big.NewInt(MaxRSAPublicExponent))))
	require.NoError(t, err, "e = MaxRSAPublicExponent is allowed")
	_, err = ParseJWK(rsaJWK(MinRSABits, exp(big.NewInt(MaxRSAPublicExponent+1))))
	require.Error(t, err, "e = MaxRSAPublicExponent+1")
	assert.Contains(t, err.Error(), "exceeds allowed maximum")

	_, err = ParseJWK(JWK{Kty: "RSA", N: b64u(bigWithBits(MinRSABits).Bytes()), E: "!!not base64!!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rsa e")

	_, err = ParseJWK(JWK{Kty: "RSA", N: "!!not base64!!", E: "AQAB"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64url")
}

func ecJWK(t *testing.T, curve elliptic.Curve, crv string) JWK {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	pub, err := k.PublicKey.Bytes()
	require.NoError(t, err)
	n := (curve.Params().BitSize + 7) / 8
	return JWK{Kty: "EC", Crv: crv, X: b64u(pub[1 : 1+n]), Y: b64u(pub[1+n:])}
}

func TestParseJWK_ECCurvesParseToTheirOwnPublicKey(t *testing.T) {
	for crv, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		jwk := ecJWK(t, curve, crv)
		key, err := ParseJWK(jwk)
		require.NoError(t, err, crv)
		pub, ok := key.(*ecdsa.PublicKey)
		require.True(t, ok, crv)
		assert.Equal(t, crv, pub.Curve.Params().Name, crv)
		xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
		require.NoError(t, err)
		assert.Equal(t, new(big.Int).SetBytes(xb), pub.X, "x survives the round trip on %s", crv) //nolint:staticcheck // reading the coordinate is the point
	}
}

func TestParseJWK_ECCoordinateSizeAndEncodingChecks(t *testing.T) {
	good := ecJWK(t, elliptic.P256(), "P-256")
	tooBig := b64u(bigWithBits(257).Bytes())

	for name, jwk := range map[string]JWK{
		"x one bit too wide": {Kty: "EC", Crv: "P-256", X: tooBig, Y: good.Y},
		"y one bit too wide": {Kty: "EC", Crv: "P-256", X: good.X, Y: tooBig},
	} {
		_, err := ParseJWK(jwk)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "exceeds curve", name)
	}

	// A coordinate of exactly the field size is not rejected by the size check
	// (it is rejected, if at all, as off-curve).
	edge := b64u(bigWithBits(256).Bytes())
	_, err := ParseJWK(JWK{Kty: "EC", Crv: "P-256", X: edge, Y: good.Y})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on curve")
	_, err = ParseJWK(JWK{Kty: "EC", Crv: "P-256", X: good.X, Y: edge})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on curve")

	_, err = ParseJWK(JWK{Kty: "EC", Crv: "P-256", X: "!!", Y: good.Y})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64url")
	_, err = ParseJWK(JWK{Kty: "EC", Crv: "P-256", X: good.X, Y: "!!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64url")

	_, err = ParseJWK(JWK{Kty: "EC", Crv: "P-192", X: good.X, Y: good.Y})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported EC curve")
	_, err = ParseJWK(JWK{Kty: "oct"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported kty")
}

func TestPATCodec_EncodeExactOutput(t *testing.T) {
	got, err := EncodePATScopes([]string{" secrets.read ", "", "audit.read", "secrets.read", "   "})
	require.NoError(t, err)
	assert.Equal(t, `["secrets.read","audit.read"]`, got)
	assert.True(t, slices.Equal([]string{"secrets.read", "audit.read"}, DecodePATScopes(got)))

	got, err = EncodePATCIDRs([]string{" 10.0.0.0/8 ", "", "10.0.0.0/8", "2001:db8::/32"})
	require.NoError(t, err)
	assert.Equal(t, `["10.0.0.0/8","2001:db8::/32"]`, got)
}

func TestPATRestriction_ExactPermissionOnly(t *testing.T) {
	r := &PATRestriction{Permissions: []string{"secrets.read"}}
	assert.True(t, r.Allows("secrets.read", Scope{}))
	assert.False(t, r.Allows("secrets.write", Scope{}), "a different permission is not allowed")
	assert.False(t, r.Allows("secrets.reader", Scope{}))
	assert.False(t, (&PATRestriction{Permissions: []string{"secrets.*"}}).Allows("audit.read", Scope{}))
	assert.True(t, (&PATRestriction{Permissions: []string{"secrets.*"}}).Allows("secrets.write", Scope{}))
	assert.True(t, (&PATRestriction{Permissions: []string{"*"}}).Allows("anything", Scope{}))
}

func TestSecretValuePolicy_MinLengthIsInclusive(t *testing.T) {
	p := SecretValuePolicy{Enabled: true, MinLength: 8}
	require.NoError(t, p.Validate([]byte("12345678")), "exactly the minimum passes")
	require.Error(t, p.Validate([]byte("1234567")), "one short fails")
	require.NoError(t, SecretValuePolicy{Enabled: true}.Validate(nil), "no minimum: an empty value is not a length problem")
}

func TestContainsPersonalInfo_ThreeCharMinimum(t *testing.T) {
	assert.True(t, containsPersonalInfo("xxBOBxx", &models.User{Username: "bob"}), "a three-character username counts")
	assert.False(t, containsPersonalInfo("xxabxx", &models.User{Username: "ab"}), "a two-character one does not")
	assert.True(t, containsPersonalInfo("xxjanexx", &models.User{Email: "jane@example.com"}), "email local part")
	assert.False(t, containsPersonalInfo("xxjanexx", &models.User{Email: "@example.com"}))
	assert.True(t, containsPersonalInfo("xxLOVELACExx", &models.User{DisplayName: "Ada Lovelace"}), "a display-name word")
	assert.False(t, containsPersonalInfo("xxadaxx", &models.User{DisplayName: "Ad Ba"}))
}

// MinSCIMTokenDistinctBytes etc. are covered by the existing shape tests; these
// pin the letter-splitting edges of the placeholder-word rule.
func TestCheckSCIMTokenShape_PlaceholderWordEdges(t *testing.T) {
	digits := "0123456789"
	// Exactly four letters, which form one four-letter word, is refused.
	require.Error(t, CheckSCIMTokenShape("test"+digits+digits, nil), "four letters, one word")
	// A 'z' is a letter: it keeps the letters from splitting into placeholder words.
	require.NoError(t, CheckSCIMTokenShape("test"+digits+"z"+digits, nil), "z is counted as a letter")
	// Short words alone (no word of four or more letters) are not a sample value.
	require.NoError(t, CheckSCIMTokenShape("me-my-a-key-"+digits+digits, nil), "only short placeholder words")
	// Words that do not split the letters completely are not refused.
	require.NoError(t, CheckSCIMTokenShape("test-qq-"+digits+digits, nil))
	// A long word split into several known words is refused.
	require.Error(t, CheckSCIMTokenShape("your-test-token-"+digits, nil))
	assert.True(t, strings.Contains(scimTokenShapeProblem("test"+digits+digits), "placeholder words"))
}

// A token made only of letters has no spare capacity in onlyPlaceholderWords'
// letter buffer: the word match must stop at the end of the letters instead of
// slicing past them.
func TestCheckSCIMTokenShape_AllLettersTokenDoesNotOverrun(t *testing.T) {
	require.NotPanics(t, func() {
		require.NoError(t, CheckSCIMTokenShape("qwxzjkvbnmpqwxzjkvbnmpqx", nil))
	})
	assert.False(t, onlyPlaceholderWords("qwxzjkvbnmpqwxzjkvbnmpqxtok"))
	assert.False(t, onlyPlaceholderWords("testtokenx"), "the letters do not split completely")
	assert.True(t, onlyPlaceholderWords("testtoken"))
}
