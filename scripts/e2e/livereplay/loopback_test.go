package livereplay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateLoopbackURL(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:9", "https://[::1]:443"} {
		if err := validateLoopbackURL(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://203.0.113.5:80", "http://example.com", "http://169.254.169.254", "http://127.0.0.1@evil.com", "file:///etc/passwd", ""} {
		if err := validateLoopbackURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// World.Do must refuse a non-loopback BaseURL before any request is built.
func TestWorldDoRefusesNonLoopback(t *testing.T) {
	w := NewWorld("http://203.0.113.5:80", &Spec{})
	_, _, err := w.Do(nil, "GET", "/health", nil)
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("want not-loopback refusal, got %v", err)
	}
}

func TestWorldDoLoopbackStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()
	w := NewWorld(srv.URL, &Spec{})
	st, b, err := w.Do(nil, "GET", "/p", nil)
	if err != nil || st != 200 || string(b) != "pong" {
		t.Fatalf("st=%d b=%q err=%v", st, b, err)
	}
}
