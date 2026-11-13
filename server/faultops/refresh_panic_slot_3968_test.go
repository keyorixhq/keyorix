// refresh_panic_slot_3968_test.go -- regression guard for #3968.
//
// POST /auth/refresh with a storage PANIC used to end in the Recovery 500 and
// keep the per-IP login-attempt slot RefreshToken reserved (oracle (a),
// [LoginAttempt] changed), whatever the call. RefreshSession now recovers each
// storage call's panic into that call's error path (refreshStorageCall):
//
//	GetSessionAny#1 panic (a300d20001)  pre-verdict: slot back, no diff, no row needed
//	GetUser#1 panic       (a300dc0001)  post-verdict: slot kept, 503 (post_auth_refresh_getuser_panic)
//	RotateSession#1 panic (a301970001)  post-verdict: slot kept, 401 (post_auth_refresh_rotatesession_panic)
//
// The #3968 knownOpenTolerances rows are gone. The run below also drops any
// #3968 row that might still be registered, so it cannot pass on a tolerance.
// Inputs are addressed by (op key, method name), so they cannot drift.
package faultops

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestRefreshStoragePanicTakesTheErrorPath_3968(t *testing.T) {
	real := knownOpenTolerances
	var kept []knownOpenTolerance
	for _, k := range real {
		if k.issue != "#3968" {
			kept = append(kept, k)
		}
	}
	knownOpenTolerances = kept
	t.Cleanup(func() { knownOpenTolerances = real })

	// The panic rows (like their error twins) do not pin the response, so the
	// answer each panic must get -- its error twin's -- is pinned here: a panic
	// that slid back to the Recovery 500 fails even with the rows registered.
	const op = "REST POST /auth/refresh"
	for _, tc := range []struct{ method, wantStatus string }{
		{"GetSessionAny", "HTTP 503"},
		{"GetUser", "HTTP 503"},
		{"RotateSession", "HTTP 401"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			data := legacyFuzzInputFor(t, op, tc.method, 1, faultstorage.KindPanic)
			t.Log(traceFuzzOp(data))
			observed := false
			runOneFuzzIterationWithWorlds(t, data, nil, nil, func(in oracleInput) {
				observed = true
				if !strings.HasPrefix(in.result.Detail, tc.wantStatus+":") {
					t.Errorf("%s#1 panic answered %q, want its error twin's %s", tc.method, in.result.Detail, tc.wantStatus)
				}
			})
			if !observed {
				t.Fatalf("%s#1 panic: the oracle never ran (fault did not fire or the run was skipped)", tc.method)
			}
		})
	}
}
