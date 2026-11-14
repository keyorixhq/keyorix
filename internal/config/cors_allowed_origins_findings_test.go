package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/cors"
)

// TestAllowedOriginsFindingWildcardEntry pins finding LF1-CORS-wildcard-entry.
// validateAllowedOrigins refuses a bare "*" because "a wildcard origin defeats the CORS
// allowlist", but it accepts "https://*" (url.Parse takes "*" as a host), and go-chi/cors
// treats that entry as the pattern "https://" + anything. With router.go's options
// (AllowCredentials true) every https origin then gets a credentialed grant: the same
// effect the bare "*" ban exists to prevent, for https pages. "https://*.example.com"
// likewise turns an exact-origin list into a subdomain pattern the validator's doc
// comment does not describe.
//
// This test goes red when validateAllowedOrigins rejects '*' inside an entry (or
// go-chi/cors stops treating it as a wildcard); then drop the wildcard branch in
// checkCORSGrant together with this test.
//
// What this does NOT verify: attacker reach. server.http.allowed_origins is operator
// configuration, so this is a guard gap (HARDENING), not something a remote party can
// set.
func TestAllowedOriginsFindingWildcardEntry(t *testing.T) {
	list := []string{"https://*"}
	if err := validateAllowedOrigins(list); err != nil {
		t.Fatalf("validateAllowedOrigins now rejects %q (%v): finding fixed", list, err)
	}
	h := cors.Handler(corsTestOptions(list))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://attacker.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q: go-chi/cors no longer treats the entry as a wildcard", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("grant is no longer credentialed")
	}
}
