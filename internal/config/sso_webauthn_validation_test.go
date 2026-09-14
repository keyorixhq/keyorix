// sso_webauthn_validation_test.go covers the config-time hardening validators
// added from the 2026-09-14 adversarial review: F3 (allow_idp_initiated refused),
// F4 (SSO client_id must not double as a machine-federation audience for the same
// issuer), and F5 (WebAuthn rp_origins are https + within rp_id). Each case is
// exercised in BOTH directions — a known-good config passes and a known-bad one
// fails — so the guard can never silently pass everything (CLAUDE.md: "confirm it
// is green on a known-good case as well as red on a known-bad one").
package config

import (
	"strings"
	"testing"
)

// --- F3: allow_idp_initiated -------------------------------------------------

func TestValidateSSOIDPInitiated_RejectsEnabled(t *testing.T) {
	sso := SSOConfig{Providers: []SSOProviderConfig{
		{Name: "corp", Type: "saml", SAML: &SAMLProviderConfig{AllowIDPInitiated: true}},
	}}
	err := validateSSOIDPInitiated(sso)
	if err == nil {
		t.Fatal("allow_idp_initiated: true must be rejected")
	}
	if !strings.Contains(err.Error(), "corp") {
		t.Errorf("error must name the offending provider, got: %v", err)
	}
}

func TestValidateSSOIDPInitiated_AllowsDisabledAndOIDC(t *testing.T) {
	sso := SSOConfig{Providers: []SSOProviderConfig{
		{Name: "corp", Type: "saml", SAML: &SAMLProviderConfig{AllowIDPInitiated: false}},
		{Name: "okta", Type: "oidc", Issuer: "https://idp.example", ClientID: "c"},
	}}
	if err := validateSSOIDPInitiated(sso); err != nil {
		t.Fatalf("a SAML provider with allow_idp_initiated:false alongside an OIDC provider must pass: %v", err)
	}
}

// --- F4: cross-seam audience isolation --------------------------------------

func TestValidateSSOAudienceIsolation_RejectsClientIDReuseSameIssuer(t *testing.T) {
	// Trailing-slash difference on the issuer must not defeat the match.
	c := &Config{
		SSO: SSOConfig{Providers: []SSOProviderConfig{
			{Name: "okta", Type: "oidc", Issuer: "https://idp.example/", ClientID: "shared-client"},
		}},
		OIDC: OIDCConfig{Enabled: true, Issuers: []OIDCIssuerConfig{
			{Name: "ci", Issuer: "https://idp.example", Audiences: []string{"other", "shared-client"}},
		}},
	}
	err := validateSSOAudienceIsolation(c)
	if err == nil {
		t.Fatal("an sso client_id reused as a machine-federation audience for the same issuer must be rejected")
	}
	if !strings.Contains(err.Error(), "okta") {
		t.Errorf("error must name the offending sso provider, got: %v", err)
	}
}

func TestValidateSSOAudienceIsolation_AllowsSafeShapes(t *testing.T) {
	cases := []struct {
		name string
		c    *Config
	}{
		{"same issuer, distinct audience", &Config{
			SSO:  SSOConfig{Providers: []SSOProviderConfig{{Name: "okta", Type: "oidc", Issuer: "https://idp.example", ClientID: "sso-client"}}},
			OIDC: OIDCConfig{Enabled: true, Issuers: []OIDCIssuerConfig{{Name: "ci", Issuer: "https://idp.example", Audiences: []string{"machine-aud"}}}},
		}},
		{"same client_id, different issuer (machine seam exact-issuer match blocks confusion)", &Config{
			SSO:  SSOConfig{Providers: []SSOProviderConfig{{Name: "okta", Type: "oidc", Issuer: "https://sso.example", ClientID: "shared"}}},
			OIDC: OIDCConfig{Enabled: true, Issuers: []OIDCIssuerConfig{{Name: "ci", Issuer: "https://ci.example", Audiences: []string{"shared"}}}},
		}},
		{"machine federation disabled", &Config{
			SSO:  SSOConfig{Providers: []SSOProviderConfig{{Name: "okta", Type: "oidc", Issuer: "https://idp.example", ClientID: "shared"}}},
			OIDC: OIDCConfig{Enabled: false, Issuers: []OIDCIssuerConfig{{Name: "ci", Issuer: "https://idp.example", Audiences: []string{"shared"}}}},
		}},
		{"saml provider client_id is not an oidc id_token audience", &Config{
			SSO:  SSOConfig{Providers: []SSOProviderConfig{{Name: "corp", Type: "saml", ClientID: "shared", SAML: &SAMLProviderConfig{}}}},
			OIDC: OIDCConfig{Enabled: true, Issuers: []OIDCIssuerConfig{{Name: "ci", Issuer: "https://idp.example", Audiences: []string{"shared"}}}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSSOAudienceIsolation(tc.c); err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

// --- F5: WebAuthn RP origins ------------------------------------------------

func TestValidateWebAuthnRP(t *testing.T) {
	cases := []struct {
		name    string
		wc      WebAuthnConfig
		wantErr bool
	}{
		{"disabled ignores everything", WebAuthnConfig{Enabled: false, RPOrigins: []string{"http://evil"}}, false},
		{"valid https exact host", WebAuthnConfig{Enabled: true, RPID: "keyorix.example.com", RPOrigins: []string{"https://keyorix.example.com"}}, false},
		{"valid https subdomain", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"https://app.example.com"}}, false},
		{"valid https with port", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"https://app.example.com:8443"}}, false},
		{"loopback http allowed", WebAuthnConfig{Enabled: true, RPID: "localhost", RPOrigins: []string{"http://localhost"}}, false},
		{"127.0.0.1 http allowed", WebAuthnConfig{Enabled: true, RPID: "localhost", RPOrigins: []string{"http://127.0.0.1:3000"}}, false},
		{"plaintext non-loopback rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"http://app.example.com"}}, true},
		{"host outside rp_id rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"https://evil.com"}}, true},
		{"suffix-trick sibling domain rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"https://notexample.com"}}, true},
		{"missing rp_id rejected", WebAuthnConfig{Enabled: true, RPOrigins: []string{"https://example.com"}}, true},
		{"no origins rejected", WebAuthnConfig{Enabled: true, RPID: "example.com"}, true},
		{"non-http(s) scheme rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"ftp://example.com"}}, true},
		{"unparseable origin rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"://nope"}}, true},
		{"one bad among several rejected", WebAuthnConfig{Enabled: true, RPID: "example.com", RPOrigins: []string{"https://app.example.com", "https://evil.com"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebAuthnRP(tc.wc)
			if tc.wantErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}
