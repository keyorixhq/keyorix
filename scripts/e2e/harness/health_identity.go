// No build tag, unlike the rest of this package: this file is pure
// decision logic (no subprocesses, no ports, no `go build`), so its unit
// test runs in the default `go test ./...` on every PR. The rest of the
// harness only runs in tagged e2e jobs, and the upgrade path in particular
// only runs nightly -- which is how #2596 (the nonce check below rejecting
// every pre-nonce release binary) reached main unnoticed.

package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// portConflictError records a /health 200 that did not come from the child
// this boot started -- live proof a different process is bound to this
// exact port right now (#2459).
type portConflictError struct {
	got, want string
	// detail, when set, replaces the default nonce-mismatch explanation
	// (used for the pre-nonce access-log check, where there is no foreign
	// nonce to report).
	detail string
}

func (e *portConflictError) Error() string {
	if e.detail != "" {
		return e.detail
	}
	return fmt.Sprintf("health check answered with a different server's instance_nonce (got %q, want %q)", e.got, e.want)
}

// checkHealthIdentity decides whether a 200 /health body came from the
// child process this boot started. It returns nil when it did, a
// *portConflictError when it did not, or a decode error.
//
// Two proofs, chosen by preNonceBinary:
//
//   - preNonceBinary false (every binary built from this checkout): the
//     body's instance_nonce must equal wantNonce. Anything else, empty
//     included, is a conflict. servedByChild is never called.
//   - preNonceBinary true (a release binary older than
//     KEYORIX_E2E_INSTANCE_NONCE support, e.g. the upgrade path's
//     v0.95.1 -- #2596): such a binary always answers with an empty nonce,
//     so the nonce cannot prove anything. A NON-empty nonce that isn't
//     wantNonce still means a nonce-aware server from another boot owns the
//     port: conflict. An empty nonce is accepted only if servedByChild
//     reports that this boot's own child logged serving this very request
//     (see accessLogShowsClient).
//
// What this does NOT cover: under preNonceBinary, a foreign process whose
// log is not this child's log cannot fake an entry in it, so the only
// accepted case is our child genuinely serving the probe; but if the old
// binary's access-log format ever stops matching accessLogShowsClient, the
// check fails closed (every boot is reported as a conflict), never open.
func checkHealthIdentity(body []byte, wantNonce string, preNonceBinary bool, servedByChild func() bool) error {
	var health struct {
		InstanceNonce string `json:"instance_nonce"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return fmt.Errorf("decode /health response: %w\nbody: %s", err, body)
	}
	if health.InstanceNonce == wantNonce {
		return nil
	}
	if !preNonceBinary || health.InstanceNonce != "" {
		return &portConflictError{got: health.InstanceNonce, want: wantNonce}
	}
	if servedByChild() {
		return nil
	}
	return &portConflictError{
		want: wantNonce,
		detail: "health check answered 200 with no instance_nonce (pre-nonce binary), but this boot's own " +
			"child never logged serving that request -- a different process answered on this port",
	}
}

// accessLogShowsClient reports whether a keyorix-server log contains the
// access-log line for a request from clientAddr (the probe connection's own
// local "ip:port") that was answered 200. The server's request logger
// (chi's middleware.Logger format) writes, e.g.:
//
//	"GET http://127.0.0.1:33223/health HTTP/1.1" from 127.0.0.1:53336 - 200 90B in 127.327µs
//
// The trailing " - 200 " anchors the port, so 127.0.0.1:5333 does not
// match a line for 127.0.0.1:53336. The client port is chosen by the
// kernel for the probe's own connection, so only the process that accepted
// that connection can have logged it.
func accessLogShowsClient(log []byte, clientAddr string) bool {
	if clientAddr == "" {
		return false
	}
	return bytes.Contains(log, []byte(" from "+clientAddr+" - 200 "))
}
