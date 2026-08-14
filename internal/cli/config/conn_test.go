package config

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	appconfig "github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func cfgFor(url string) *appconfig.Config {
	c := &appconfig.Config{}
	c.Storage.Remote = &appconfig.RemoteConfig{BaseURL: url, TLSVerify: appconfig.BoolPtr(false)}
	return c
}

func TestTestRemoteConnection_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // unauthenticated probe still proves reachability
	}))
	defer srv.Close()

	if err := testRemoteConnection(cfgFor(srv.URL)); err != nil {
		t.Fatalf("expected reachable server to pass, got %v", err)
	}
}

func TestTestRemoteConnection_Unreachable(t *testing.T) {
	// Closed server → connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	if err := testRemoteConnection(cfgFor(url)); err == nil {
		t.Fatal("expected an error reaching a closed server, got nil")
	}
}

func TestTestRemoteConnection_NoURL(t *testing.T) {
	if err := testRemoteConnection(cfgFor("")); err == nil {
		t.Fatal("expected an error when base URL is unset, got nil")
	}
}

// TestTestRemoteConnection_WarnsUntrustedConfigSource is #G73: this issues an
// outbound HTTP request (SSRF exposure) to a server URL sourced from
// ./keyorix.yaml — an untrusted, CWD-relative, attacker-plantable file — with
// no warning that the target came from there. Must warn the same way
// internal/cli/common.ResolveRemote's other CLI callers already do.
func TestTestRemoteConnection_WarnsUntrustedConfigSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	out := captureStderr(t, func() {
		require.NoError(t, testRemoteConnection(cfgFor(srv.URL)))
	})
	assert.Contains(t, out, "keyorix.yaml")
	assert.Contains(t, out, "malicious file")
}
