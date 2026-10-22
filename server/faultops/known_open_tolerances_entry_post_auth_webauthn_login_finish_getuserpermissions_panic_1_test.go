// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// release/v0.96.x only (REL-0963, v0.96.3). A panic in the post-verdict identity
	// read GetUserPermissions on REST POST /auth/webauthn/login/finish is answered by
	// the Recovery 500 instead of being denied like the error kind, and the request
	// keeps its LoginAttempt slot: oracle (a) reports [LoginAttempt]. Main fixed this
	// in #3267 (with #3277) and carries panic by-design rows; the release branch has
	// neither, so FuzzStorageFaultOperations finds it deterministically (input
	// d832123231, found on #3521's fuzz shard 4). v0.96.2 has the same behaviour: it is
	// not a regression of v0.96.3.
	//
	// Remove when #3540 is fixed: the v0.96.4 backport of #3267+#3277 retires this
	// row. Any further case of this family on the release branch gets its own row
	// against #3540, scoped to that one op/method/kind/nth; do not widen this one.
	registerKnownOpenTolerance("post_auth_webauthn_login_finish_getuserpermissions_panic_1", knownOpenTolerance{
		op: "REST POST /auth/webauthn/login/finish", method: "GetUserPermissions", kind: faultstorage.KindPanic,
		nth: 1, oracle: "a", issue: "#3540", expires: "2026-11-05",
		tables:     []string{"LoginAttempt"},
		findingDoc: "#3540",
	})
}
