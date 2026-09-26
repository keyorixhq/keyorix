package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CLI-APICLIENT-001 regression guard: newAPIClient must build its apiclient.Client with
// apiclient.NewHardenedHTTPClient (timeout, response-size cap, redirect refusal) -- not
// the generated client's bare &http.Client{} default. Exercises the wiring specifically
// (internal/apiclient/hardened_client_test.go already covers NewHardenedHTTPClient's own
// behavior in isolation).
func TestNewAPIClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	client, err := newAPIClient(redirector.URL, "test-token")
	if err != nil {
		t.Fatalf("newAPIClient: %v", err)
	}

	resp, err := client.GetVersionWithResponse(t.Context())
	if err == nil {
		t.Fatalf("expected the redirect to be refused, got HTTP %d", resp.StatusCode())
	}
	if !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("expected a 'refusing to follow redirect' error, got: %v", err)
	}
}
