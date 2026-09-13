package notary

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// openFDCount returns the number of open file descriptors for this process on
// Linux (the rigs), or -1 elsewhere (macOS dev has no /proc), where the caller
// skips the fd-leak check. Reading /proc/self/fd opens and closes one dir handle,
// negligible against the leak ceiling.
func openFDCount() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// FuzzVerifyReceipt feeds arbitrary bytes as an RFC 3161 TimeStampToken into
// VerifyReceipt. The fuzz target is the two external ASN.1/DER parsers inside:
// digitorus/timestamp.Parse (RFC 3161 token structure) and digitorus/pkcs7.Parse
// (PKCS#7 envelope). Both must return errors on malformed input, never panic.
//
// An empty but non-nil CertPool is used so the fuzzer bypasses the nil-roots
// guard and reaches the parse layers. Chain verification will always fail (no
// trusted root is configured), which is fine — the goal is parser robustness, not
// valid receipt verification.
func FuzzVerifyReceipt(f *testing.F) {
	roots := x509.NewCertPool() // non-nil → reaches timestamp.Parse; empty → chain always fails
	message := []byte("fuzz anchor message")

	f.Add([]byte{})
	f.Add([]byte("not DER at all"))
	// Minimal DER SEQUENCE (empty) — a structurally recognisable starting point
	// for the mutator to build valid-ish DER from.
	f.Add([]byte{0x30, 0x00})
	// SEQUENCE with one content byte.
	f.Add([]byte{0x30, 0x01, 0x00})
	// Claimed length longer than actual content — classic DER truncation.
	f.Add([]byte{0x30, 0x10, 0x00})

	f.Fuzz(func(t *testing.T, token []byte) {
		var verr error
		fuzzutil.Guard(t.Fatalf, "VerifyReceipt", func() { _, verr = VerifyReceipt(roots, message, token) })
		// Rejection invariant: roots is an EMPTY trust pool, so nothing can chain to
		// a trusted anchor — VerifyReceipt must ALWAYS return an error. A nil error
		// means a receipt was accepted with no trust anchor configured (a critical
		// verification bypass). The fuzzer cannot forge a chain to a root that does
		// not exist, so this yields no false positives.
		if verr == nil {
			t.Fatalf("BYPASS: VerifyReceipt accepted a receipt against an EMPTY trust pool: token=%x", token)
		}
	})
}

// FuzzRFC3161Anchor is #G61's continuous-fuzz counterpart to FuzzVerifyReceipt:
// Anchor() hands the TSA response body to digitorus/timestamp.ParseResponse,
// the same parser family, so a malformed/hostile response must never panic
// the process — only ever return an error.
func FuzzRFC3161Anchor(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not DER at all"))
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x01, 0x00})
	f.Add([]byte{0x30, 0x10, 0x00})
	f.Add([]byte{0x30, 0x81})
	f.Add([]byte{0x30, 0x82})
	f.Add([]byte{0xff, 0x81})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, body []byte) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}))
		r, err := NewRFC3161(srv.URL, defaultTimeout)
		if err != nil {
			srv.Close()
			t.Fatalf("unexpected NewRFC3161 error for loopback test server URL: %v", err)
		}
		fuzzutil.Guard(t.Fatalf, "RFC3161.Anchor", func() { _, _ = r.Anchor(context.Background(), []byte("fuzz anchor message")) })
		srv.Close()
		// Goroutine-leak tripwire: steady state is O(10); a per-input leak in Anchor
		// or the httptest teardown accumulates across the worker's inputs and crosses
		// this generous absolute ceiling. Absolute (not a strict per-input delta) so
		// brief connection-teardown goroutines don't cause flaky failures.
		if n := runtime.NumGoroutine(); n > 1000 {
			t.Fatalf("goroutine leak: %d goroutines after RFC3161.Anchor (expected O(10))", n)
		}
		// fd-leak tripwire (Linux rigs; skipped on macOS dev). Same rationale as the
		// goroutine check: a per-input descriptor leak (unclosed conn/listener)
		// accumulates across the worker's inputs and crosses this generous ceiling.
		if fd := openFDCount(); fd > 1000 {
			t.Fatalf("fd leak: %d open descriptors after RFC3161.Anchor (expected O(10))", fd)
		}
	})
}
