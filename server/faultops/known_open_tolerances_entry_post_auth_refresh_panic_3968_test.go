// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

// #3968: a storage PANIC inside RefreshSession is not recovered, so POST /auth/refresh
// ends in the Recovery 500 and keeps the per-IP login-attempt slot it reserved
// (oracle (a), [LoginAttempt]). Found by TestOpFaultSweep on origin/main @ f4e9f4a57
// (inputs a300d20001, a300dc0001, a301970001), identical with and without
// AUTH-LANE-FOLDS-1. One row per (method, nth 1, panic), LoginAttempt only. Remove
// when #3968 is fixed.
func init() {
	for _, r := range []struct{ name, method string }{
		{"getsessionany", "GetSessionAny"},
		{"getuser", "GetUser"},
		{"rotatesession", "RotateSession"},
	} {
		registerKnownOpenTolerance("post_auth_refresh_"+r.name+"_1_panic_3968", knownOpenTolerance{
			op: "REST POST /auth/refresh", method: r.method, nth: 1, kind: faultstorage.KindPanic,
			oracle: "a", tables: []string{"LoginAttempt"},
			issue: "#3968", expires: "2026-12-31", findingDoc: "#3968",
		})
	}
}
