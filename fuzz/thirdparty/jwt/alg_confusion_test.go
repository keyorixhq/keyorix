// Algorithm-confusion oracles for golang-jwt/jwt/v5 as configured by Keyorix
// (asymmetric-only WithValidMethods allowlist, keyfunc returns an asymmetric
// public key selected by issuer+kid). Each oracle pairs a GREEN assertion (the
// Keyorix configuration rejects the attack) with a RED PROOF (a deliberately
// vulnerable local parser configuration accepts the same bytes), so the test
// demonstrates the guard actually fires and is not vacuous. The red-proof
// configurations are built entirely in-test; NO production code is modified.
//
// Reachability: the Keyorix configuration mirrored here is the exact one in
// internal/oidcverify OIDCVerifier.VerifyWithExpiry and internal/core KeyorixCore.verifyIDToken — the two live
// JWT verification paths (machine-token federation and SSO human login).
//
// What this does NOT verify: the real JWKS fetch/caching (internal/oidcverify/
// oidc_jwks.go), the post-parse claim policy, or Ed25519 (Keyorix's allowlist
// excludes EdDSA, so a valid EdDSA token is correctly rejected — asserted below).
package jwthostile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// keyorixParser builds a parser with Keyorix's exact asymmetric-only allowlist.
func keyorixParser() *jwt.Parser {
	return jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
}

func validClaims() jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   "alice",
		Issuer:    "https://issuer.example",
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return k
}

func rsaPublicPEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Oracle: a token with alg="none" is rejected by the Keyorix configuration.
func TestAlgConfusion_NoneRejected(t *testing.T) {
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims()).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("mint none token: %v", err)
	}
	rsaKey := mustRSA(t)
	keyfunc := func(*jwt.Token) (any, error) { return &rsaKey.PublicKey, nil }

	// GREEN: Keyorix rejects (none not in the method allowlist).
	if _, err := keyorixParser().Parse(tok, keyfunc); err == nil {
		t.Fatalf("GUARD FAILED: Keyorix parser accepted an alg=none token")
	}

	// RED PROOF: a parser with no method allowlist and a none-accepting keyfunc
	// accepts the same bytes — proving the oracle distinguishes the two configs.
	vuln := jwt.NewParser()
	noneKeyfunc := func(*jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil }
	if _, err := vuln.Parse(tok, noneKeyfunc); err != nil {
		t.Fatalf("RED PROOF INVALID: even the vulnerable config rejected alg=none (%v) — the oracle would be vacuous", err)
	}
}

// Oracle: an HS256 token forged with the RSA PUBLIC key as the HMAC secret (the
// classic asymmetric->symmetric confusion) is rejected by the Keyorix config.
func TestAlgConfusion_HS256WithRSAPublicKeyRejected(t *testing.T) {
	rsaKey := mustRSA(t)
	pubPEM := rsaPublicPEM(t, rsaKey)

	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims()).SignedString(pubPEM)
	if err != nil {
		t.Fatalf("forge HS256: %v", err)
	}
	// Keyorix's keyfunc returns the RSA public key (as the real one does).
	keyorixKeyfunc := func(*jwt.Token) (any, error) { return &rsaKey.PublicKey, nil }

	// GREEN: rejected (HS256 not in allowlist; also wrong key type for HMAC).
	if _, err := keyorixParser().Parse(forged, keyorixKeyfunc); err == nil {
		t.Fatalf("GUARD FAILED: Keyorix parser accepted an HS256-with-RSA-public-key forgery")
	}

	// RED PROOF: a parser allowing HS256 whose keyfunc hands the public-key PEM
	// bytes to the HMAC verifier accepts the forgery.
	vuln := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
	vulnKeyfunc := func(*jwt.Token) (any, error) { return pubPEM, nil }
	if _, err := vuln.Parse(forged, vulnKeyfunc); err != nil {
		t.Fatalf("RED PROOF INVALID: vulnerable HS256 config rejected the forgery (%v)", err)
	}
}

// Oracle: an RS256-signed token presented with a PS256 header (or verified as PS)
// does not verify — the signing method and header alg must agree.
func TestAlgConfusion_RSvsPSRejected(t *testing.T) {
	rsaKey := mustRSA(t)
	keyfunc := func(*jwt.Token) (any, error) { return &rsaKey.PublicKey, nil }

	rsToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims()).SignedString(rsaKey)
	if err != nil {
		t.Fatalf("mint RS256: %v", err)
	}
	// Sanity: the honest RS256 token verifies.
	if _, err := keyorixParser().Parse(rsToken, keyfunc); err != nil {
		t.Fatalf("honest RS256 token failed to verify: %v", err)
	}
	// Forge a header that claims PS256 while the signature is RS256 (PKCS#1 v1.5).
	psHeaderToken := reSignHeaderAlg(t, rsToken, "PS256")
	if _, err := keyorixParser().Parse(psHeaderToken, keyfunc); err == nil {
		t.Fatalf("GUARD FAILED: RS256 signature accepted under a PS256 header")
	}
}

// Oracle: an ES256 (P-256) token does not verify against a P-384 public key, and
// an ES256 token presented with an ES384 header is rejected (curve/method mismatch).
func TestAlgConfusion_ECCurveMismatchRejected(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256 keygen: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 keygen: %v", err)
	}
	es256, err := jwt.NewWithClaims(jwt.SigningMethodES256, validClaims()).SignedString(p256)
	if err != nil {
		t.Fatalf("mint ES256: %v", err)
	}
	// honest verify against the right curve.
	if _, err := keyorixParser().Parse(es256, func(*jwt.Token) (any, error) { return &p256.PublicKey, nil }); err != nil {
		t.Fatalf("honest ES256 failed to verify: %v", err)
	}
	// wrong-curve public key: must fail.
	if _, err := keyorixParser().Parse(es256, func(*jwt.Token) (any, error) { return &p384.PublicKey, nil }); err == nil {
		t.Fatalf("GUARD FAILED: ES256 token verified against a P-384 public key")
	}
	// ES384 header over an ES256 signature: method mismatch, must fail.
	es384Header := reSignHeaderAlg(t, es256, "ES384")
	if _, err := keyorixParser().Parse(es384Header, func(*jwt.Token) (any, error) { return &p256.PublicKey, nil }); err == nil {
		t.Fatalf("GUARD FAILED: ES256 signature accepted under an ES384 header")
	}
}

// Oracle: EdDSA is NOT in Keyorix's allowlist, so even a valid EdDSA token is
// rejected (positive confirmation the allowlist is exhaustive, not a denylist).
func TestAlgConfusion_EdDSAOutsideAllowlistRejected(t *testing.T) {
	_, priv, err := ed25519KeyPair()
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims()).SignedString(priv)
	if err != nil {
		t.Fatalf("mint EdDSA: %v", err)
	}
	if _, err := keyorixParser().Parse(tok, func(*jwt.Token) (any, error) { return priv.Public(), nil }); err == nil {
		t.Fatalf("GUARD FAILED: Keyorix parser accepted an EdDSA token outside its allowlist")
	}
}
