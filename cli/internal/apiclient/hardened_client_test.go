package apiclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CLI-APICLIENT-001 regression guard: the generated client's default http.Client{} has
// no timeout, no response-size cap, and no redirect refusal. These tests exercise
// NewHardenedHTTPClient directly against real httptest servers -- no mocking of
// net/http internals.

func TestHardenedClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	c := NewHardenedHTTPClient()
	resp, err := c.Get(redirector.URL) //nolint:noctx
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err == nil {
		t.Fatalf("expected the redirect to be refused, got a response with status %v", resp.Status)
	}
	if !strings.Contains(err.Error(), "refusing to follow redirect") {
		t.Fatalf("expected a 'refusing to follow redirect' error, got: %v", err)
	}
}

func TestHardenedClient_CapsResponseBodySize(t *testing.T) {
	oversized := make([]byte, maxResponseBodyBytes+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	c := NewHardenedHTTPClient()
	resp, err := c.Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("expected reading an oversized body to fail")
	}
	if !strings.Contains(err.Error(), "exceeds the maximum allowed size") {
		t.Fatalf("expected ErrResponseTooLarge, got: %v", err)
	}
}

func TestHardenedClient_AllowsNormalResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewHardenedHTTPClient()
	resp, err := c.Get(srv.URL) //nolint:noctx
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestHardenedClient_HasATimeout(t *testing.T) {
	c := NewHardenedHTTPClient()
	if c.Timeout <= 0 {
		t.Fatalf("expected a positive request timeout, got %v", c.Timeout)
	}
}
