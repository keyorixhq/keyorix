package core

// jwt_future_iat_crit_closure_test.go — dedicated, unambiguous proving tests
// for docs/security-closures.tsv (oidc-future-iat-001/-002,
// oidc-crit-header-001/-002; see docs/findings/2026-09-23-FINDING-oidc-future-iat-and-crit.md).
// FuzzOIDCIDTokenSingleConstraintViolation / FuzzSSOIDTokenSingleConstraintViolation
// already cover both claims via committed seeds, but each fuzz target's name
// is shared across every violation kind it exercises — check-closures.sh's
// claim-name lookup needs one (package, test) pair per claim, so these give
// each claim its own name, matching the awssm/azurekv-empty-secret-response
// convention (jwt_not_enforced_report_test.go's doc comment for why AND
// awssm-empty-secret-response-001/azurekv-empty-secret-response-001 in
// docs/security-closures.tsv for precedent).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func TestOIDCVerifier_RejectsFutureIssuedAt(t *testing.T) {
	const trustedIss = "https://k8s.local"
	const trustedAud = "keyorix"
	const trustedKid = "kid-1"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: trustedIss, Audiences: []string{trustedAud}}},
		staticResolver{kid: trustedKid, key: &key.PublicKey},
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := oidcSingleConstraintBaseClaims(now, "sa-future-iat", trustedIss, trustedAud)
	applySharedJWTViolation(jwtViolationIatFutureBeyondLeeway, claims, now, trustedIss, trustedAud, oidcClockSkew)
	raw := signJWTViolation(t, jwtViolationIatFutureBeyondLeeway, claims, key, trustedKid)

	if _, _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("OIDCVerifier.Verify accepted a token with iat far in the future")
	}
}

func TestSSOVerifyIDToken_RejectsFutureIssuedAt(t *testing.T) {
	const trustedIss = "https://idp.test"
	const clientID = "client-1"
	const trustedKid = "kid-1"
	const correctNonce = "expected-nonce-value"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &KeyorixCore{now: time.Now, ssoJWKS: staticResolver{kid: trustedKid, key: &key.PublicKey}}
	p := &SSOProvider{Name: "okta", Issuer: trustedIss, ClientID: clientID}

	now := time.Now()
	claims := ssoSingleConstraintBaseClaims(now, "sub-future-iat", trustedIss, clientID, correctNonce)
	applySharedJWTViolation(jwtViolationIatFutureBeyondLeeway, claims, now, trustedIss, clientID, ssoClockSkew)
	raw := signJWTViolation(t, jwtViolationIatFutureBeyondLeeway, claims, key, trustedKid)

	if _, _, _, _, err := c.verifyIDToken(context.Background(), p, correctNonce, raw); err == nil {
		t.Fatal("verifyIDToken accepted a token with iat far in the future")
	}
}

func TestOIDCVerifier_RejectsCritHeader(t *testing.T) {
	const trustedIss = "https://k8s.local"
	const trustedAud = "keyorix"
	const trustedKid = "kid-1"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: trustedIss, Audiences: []string{trustedAud}}},
		staticResolver{kid: trustedKid, key: &key.PublicKey},
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := oidcSingleConstraintBaseClaims(now, "sa-crit", trustedIss, trustedAud)
	raw := signJWTViolation(t, jwtViolationCritHeader, claims, key, trustedKid)

	if _, _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("OIDCVerifier.Verify accepted a token carrying an unrecognized crit header")
	}
}

func TestSSOVerifyIDToken_RejectsCritHeader(t *testing.T) {
	const trustedIss = "https://idp.test"
	const clientID = "client-1"
	const trustedKid = "kid-1"
	const correctNonce = "expected-nonce-value"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := &KeyorixCore{now: time.Now, ssoJWKS: staticResolver{kid: trustedKid, key: &key.PublicKey}}
	p := &SSOProvider{Name: "okta", Issuer: trustedIss, ClientID: clientID}

	now := time.Now()
	claims := ssoSingleConstraintBaseClaims(now, "sub-crit", trustedIss, clientID, correctNonce)
	raw := signJWTViolation(t, jwtViolationCritHeader, claims, key, trustedKid)

	if _, _, _, _, err := c.verifyIDToken(context.Background(), p, correctNonce, raw); err == nil {
		t.Fatal("verifyIDToken accepted a token carrying an unrecognized crit header")
	}
}
