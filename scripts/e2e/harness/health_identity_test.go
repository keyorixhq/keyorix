// No build tag: runs in the default `go test ./...` (see health_identity.go).

package harness

import (
	"errors"
	"testing"
)

// realPreNonceLog is verbatim from the v0.95.1 binary's own log in the
// failing nightly run (#2596, actions run 37112508235): the old binary
// answered /health with no instance_nonce, and its access log recorded
// serving the probe from client port 53336.
const realPreNonceLog = `2026/10/03 09:40:58 HTTP server listening on http://10.1.0.228:33223
2026/10/03 09:40:58 Audit checkpoint written: #1 head=5 events=5
2026/10/03 09:40:58 [runnervm8df0l/7jkoZBdoo4-000001] "GET http://127.0.0.1:33223/health HTTP/1.1" from 127.0.0.1:53336 - 200 90B in 127.327µs
`

// TestCheckHealthIdentity_PreNonceBinary is the #2596 regression test.
//
// Bug origin:
//
//	Introduced-by: #2477 (fix for #2459) -- pollHealthOrBindFailure began
//	  requiring /health's instance_nonce to equal the boot's nonce, but the
//	  upgrade-path test boots the previous RELEASE binary (v0.95.1), built
//	  before /health echoed KEYORIX_E2E_INSTANCE_NONCE, so it always answers
//	  with an empty nonce and every boot was reported as a port conflict.
//	Detected-by: nightly E2E smoke, e2e-smoke-upgrade leg (#2596).
//	Class: test harness -- an identity check that assumed a capability the
//	  binary under test predates.
//	Severity: CI-only; the upgrade path lost all coverage every night.
//	Guard: this test (default CI) plus TestAPISmoke_UpgradePath (nightly).
func TestCheckHealthIdentity_PreNonceBinary(t *testing.T) {
	const want = "02b8d94da088f86a4c2dc4f251739417"
	served := func() bool { return true }
	notServed := func() bool { return false }

	cases := []struct {
		name          string
		body          string
		preNonce      bool
		servedByChild func() bool
		wantConflict  bool
	}{
		{"current binary, own nonce", `{"status":"ok","instance_nonce":"` + want + `"}`, false, notServed, false},
		{"current binary, foreign nonce", `{"status":"ok","instance_nonce":"ffff"}`, false, served, true},
		// The strict contract for binaries built from this checkout is
		// unchanged: an empty nonce is a conflict even if the log matches.
		{"current binary, empty nonce", `{"status":"ok"}`, false, served, true},
		// #2596: the exact failing shape, now accepted because the child's
		// own access log proves it served the probe.
		{"pre-nonce binary, empty nonce, child served it", `{"status":"ok"}`, true, served, false},
		{"pre-nonce binary, empty nonce, child did not serve it", `{"status":"ok"}`, true, notServed, true},
		{"pre-nonce binary, foreign nonce", `{"status":"ok","instance_nonce":"ffff"}`, true, served, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHealthIdentity([]byte(tc.body), want, tc.preNonce, tc.servedByChild)
			var conflict *portConflictError
			gotConflict := errors.As(err, &conflict)
			if gotConflict != tc.wantConflict {
				t.Fatalf("conflict = %v, want %v (err: %v)", gotConflict, tc.wantConflict, err)
			}
			if !tc.wantConflict && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}

	t.Run("undecodable body is an error, not a pass", func(t *testing.T) {
		err := checkHealthIdentity([]byte("not json"), want, true, served)
		var conflict *portConflictError
		if err == nil || errors.As(err, &conflict) {
			t.Fatalf("want a decode error, got %v", err)
		}
	})
}

func TestAccessLogShowsClient(t *testing.T) {
	log := []byte(realPreNonceLog)
	cases := []struct {
		name, clientAddr string
		want             bool
	}{
		{"the probe's own connection, from the real v0.95.1 log", "127.0.0.1:53336", true},
		{"a different client port", "127.0.0.1:53337", false},
		{"a prefix of the real port must not match", "127.0.0.1:5333", false},
		{"unknown client address", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := accessLogShowsClient(log, tc.clientAddr); got != tc.want {
				t.Fatalf("accessLogShowsClient(%q) = %v, want %v", tc.clientAddr, got, tc.want)
			}
		})
	}

	t.Run("a non-200 answer from that client does not count", func(t *testing.T) {
		l := []byte(`"GET http://127.0.0.1:33223/health HTTP/1.1" from 127.0.0.1:53336 - 503 20B in 1ms` + "\n")
		if accessLogShowsClient(l, "127.0.0.1:53336") {
			t.Fatal("a 503 line was accepted as proof of a healthy answer")
		}
	})
}
