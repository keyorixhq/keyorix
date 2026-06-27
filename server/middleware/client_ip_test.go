package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveAndCaptureRemoteAddr runs the ClientIP middleware over a request and returns the
// r.RemoteAddr the downstream handler observes.
func serveAndCaptureRemoteAddr(trusted []string, remoteAddr string, headers map[string]string) string {
	var seen string
	h := ClientIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

func TestClientIP_IgnoresHeaderWhenNoTrustedProxies(t *testing.T) {
	// No trusted proxies configured → a spoofed X-Forwarded-For must be ignored and the
	// real TCP peer kept (so the rate limiter keys on the attacker's real IP).
	got := serveAndCaptureRemoteAddr(nil, "203.0.113.7:5555", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "5.6.7.8",
	})
	if got != "203.0.113.7:5555" {
		t.Errorf("RemoteAddr = %q; want the unmodified TCP peer", got)
	}
}

func TestClientIP_IgnoresHeaderWhenPeerNotTrusted(t *testing.T) {
	// A trusted proxy IS configured, but this request comes straight from an untrusted
	// peer → its spoofed header must not be honored.
	got := serveAndCaptureRemoteAddr([]string{"10.0.0.0/8"}, "203.0.113.7:5555", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	})
	if got != "203.0.113.7:5555" {
		t.Errorf("RemoteAddr = %q; want the unmodified TCP peer", got)
	}
}

func TestClientIP_HonorsHeaderFromTrustedProxy(t *testing.T) {
	// The peer is the trusted proxy → the forwarded client IP is taken.
	got := serveAndCaptureRemoteAddr([]string{"10.0.0.0/8"}, "10.1.2.3:443", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
	})
	if got != "203.0.113.9" {
		t.Errorf("RemoteAddr = %q; want the forwarded client IP", got)
	}
}

func TestClientIP_StopsAtFirstUntrustedHopFromRight(t *testing.T) {
	// XFF chain: spoofed, real-client, trusted-proxy. Walking from the right, the first
	// untrusted hop is the real client — a prepended spoofed entry is ignored.
	got := serveAndCaptureRemoteAddr([]string{"10.0.0.0/8"}, "10.1.2.3:443", map[string]string{
		"X-Forwarded-For": "9.9.9.9, 203.0.113.9, 10.4.5.6",
	})
	if got != "203.0.113.9" {
		t.Errorf("RemoteAddr = %q; want the first untrusted hop from the right", got)
	}
}

func TestClientIP_XForwardedForTakesPrecedenceOverRealIP(t *testing.T) {
	// When both headers are present, the spoof-resistant XFF walk wins over X-Real-IP,
	// so a client-supplied (possibly proxy-passed-through) X-Real-IP can't override it.
	got := serveAndCaptureRemoteAddr([]string{"10.0.0.0/8"}, "10.1.2.3:443", map[string]string{
		"X-Forwarded-For": "203.0.113.9",
		"X-Real-IP":       "6.6.6.6", // attacker-set; must be ignored in favor of XFF
	})
	if got != "203.0.113.9" {
		t.Errorf("RemoteAddr = %q; want the X-Forwarded-For client, not the X-Real-IP", got)
	}
}

func TestClientIP_RealIPOnlyWhenNoXForwardedFor(t *testing.T) {
	// X-Real-IP is honored only as a fallback when XFF is absent (and the peer is trusted).
	got := serveAndCaptureRemoteAddr([]string{"10.0.0.0/8"}, "10.1.2.3:443", map[string]string{
		"X-Real-IP": "198.51.100.7",
	})
	if got != "198.51.100.7" {
		t.Errorf("RemoteAddr = %q; want the X-Real-IP fallback", got)
	}
}

func TestClientIP_BareIPTrustedProxy(t *testing.T) {
	got := serveAndCaptureRemoteAddr([]string{"192.168.1.10"}, "192.168.1.10:8080", map[string]string{
		"X-Real-IP": "198.51.100.2",
	})
	if got != "198.51.100.2" {
		t.Errorf("RemoteAddr = %q; want the X-Real-IP from the trusted proxy", got)
	}
}
