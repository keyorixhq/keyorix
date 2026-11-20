package config

import (
	"strings"
	"testing"
)

// TestValidateAllowedOrigins_RejectsWildcardInsideEntry closes finding
// LF1-CORS-wildcard-entry (#4382). validateAllowedOrigins refused a bare "*" but
// accepted "https://*" (url.Parse takes "*" as a host), which go-chi/cors treats as
// the pattern "https://" + anything: with router.go's options (AllowCredentials true)
// every https origin then got a credentialed grant. "https://*.example.com" likewise
// turned an exact-origin list into a subdomain pattern. A '*' anywhere in an entry is
// now refused at startup.
//
// What this does NOT verify: attacker reach. server.http.allowed_origins is operator
// configuration, so this is a guard gap (HARDENING), not something a remote party can
// set.
func TestValidateAllowedOrigins_RejectsWildcardInsideEntry(t *testing.T) {
	for _, entry := range []string{"https://*", "https://*.example.com", "http://*:8080", "https://app.*"} {
		if err := validateAllowedOrigins([]string{"https://app.example.com", entry}); err == nil {
			t.Errorf("validateAllowedOrigins accepted %q", entry)
		}
	}
	if err := validateAllowedOrigins([]string{"https://app.example.com", "http://localhost:3000"}); err != nil {
		t.Fatalf("validateAllowedOrigins rejected an explicit list: %v", err)
	}
}

// TestValidateServerSection_RejectsWildcardDomain is #4382's sibling: with
// allowed_origins empty the CORS allowlist defaults to https://<server.http.domain>,
// so domain "*" or "*.example.com" became the same credentialed wildcard pattern.
func TestValidateServerSection_RejectsWildcardDomain(t *testing.T) {
	for _, domain := range []string{"*", "*.example.com"} {
		c := &Config{}
		c.Server.HTTP.Domain = domain
		err := validateServerSection(c)
		if err == nil || !strings.Contains(err.Error(), "server.http.domain") {
			t.Errorf("domain %q: got %v, want the server.http.domain refusal", domain, err)
		}
	}
	c := &Config{}
	c.Server.HTTP.Domain = "keyorix.example.com"
	if err := validateServerSection(c); err != nil && strings.Contains(err.Error(), "server.http.domain") {
		t.Fatalf("an ordinary domain was refused: %v", err)
	}
}
