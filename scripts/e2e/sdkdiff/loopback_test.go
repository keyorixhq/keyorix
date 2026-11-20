package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateLoopbackURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:9", "https://[::1]:443", "http://127.1.2.3"} {
		if err := validateLoopbackURL(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://203.0.113.5:80", "http://example.com", "http://169.254.169.254/latest", "http://127.0.0.1.evil.com",
		"http://127.0.0.1@evil.com", "ftp://127.0.0.1", "http://10.0.0.1", "", "://x",
	} {
		if err := validateLoopbackURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// apiCall (and through it the seed and login paths) must not reach a non-loopback server.
func TestApiCallRefusesNonLoopback(t *testing.T) {
	_, _, err := apiCall("GET", "http://203.0.113.5:80", "/health", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("want not-loopback refusal, got %v", err)
	}
}

func TestApiCallLoopbackStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	st, m, err := apiCall("GET", srv.URL, "/x", "", nil)
	if err != nil || st != 200 || m["ok"] != true {
		t.Fatalf("loopback call: st=%d m=%v err=%v", st, m, err)
	}
}

// A redirect off loopback is not followed.
func TestLoopbackClientRefusesRedirectOffLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.5/", http.StatusFound)
	}))
	defer srv.Close()
	resp, err := loopbackClient.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("redirect to a non-loopback host was followed")
	}
}

// The proxy refuses an upstream that is not loopback and answers 502.
func TestProxyRefusesNonLoopbackUpstream(t *testing.T) {
	p, err := NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetUpstream("http://203.0.113.5:80")
	resp, err := http.Get("http://" + p.Addr() + "/api/v1/projects")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	recs := p.Drain()
	if len(recs) != 1 || !strings.Contains(recs[0].RespBody, "not loopback") {
		t.Fatalf("recs=%+v", recs)
	}
}

// shimKeys still renames a normal body, and an over-cap body is returned untouched, not decoded.
func TestShimKeysBounded(t *testing.T) {
	small := []byte(`{"data":{"id":1,"name":"a"}}`)
	got := shimKeys(small)
	if !bytes.Contains(got, []byte(`"ID"`)) || !bytes.Contains(got, []byte(`"Name"`)) {
		t.Fatalf("normal body not shimmed: %s", got)
	}
	big := append([]byte(`{"data":{"id":1},"pad":"`), bytes.Repeat([]byte("a"), maxRespRelay)...)
	big = append(big, []byte(`"}`)...)
	out := shimKeys(big)
	if !bytes.Equal(out, big) {
		t.Fatal("oversized body was decoded/rewritten")
	}
}
