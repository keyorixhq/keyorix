package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	appconfig "github.com/keyorixhq/keyorix/internal/config"
)

func cfgFor(url string) *appconfig.Config {
	c := &appconfig.Config{}
	c.Storage.Remote = &appconfig.RemoteConfig{BaseURL: url, TLSVerify: false}
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
