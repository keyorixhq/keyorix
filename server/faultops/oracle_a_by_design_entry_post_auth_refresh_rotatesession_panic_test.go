// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3968: the panic kind of the post-verdict rotation on /auth/refresh. Same
	// decided outcome as the error row (post_auth_refresh_rotatesession):
	// RefreshSession recovers the panic into the rotation's error path
	// (refreshStorageCall), so it is the wrong-token 401 and the slot stays counted.
	registerOracleAByDesign("post_auth_refresh_rotatesession_panic", oracleAByDesignError{
		op:     "REST POST /auth/refresh",
		method: "RotateSession",
		kind:   faultstorage.KindPanic,
		nth:    1,
		tables: []string{"LoginAttempt"},
		designComment: "internal/core/auth.go RefreshSession: RotateSession runs through refreshStorageCall, " +
			"which turns its panic into an error, so the panic takes the error " +
			"row's path (the sessionWriteLanded check, then \"failed to rotate session\"), not " +
			"ErrRefreshNotEvaluated; server/http/handlers/auth.go RefreshToken answers it 401 and keeps the per-IP slot",
		provingTest: "server/http/handlers/TestRefresh_StoragePanicSlotPolicy " +
			"(every storage call refresh makes, panic kind, through middleware.Recovery: slot kept, response " +
			"byte-identical to a wrong token's); " +
			"internal/core/TestRefreshSession_PostVerdictPanicIsNotEvaluatedOnlyBeforeTheVerdict",
		why: "The token was accepted and the rotation write panicked. Recovered into the error path, the refresh " +
			"is refused with the same 401 a dead token gets and keeps the LoginAttempt slot it reserved, exactly " +
			"as for the rotation's error: returning it would make a valid token cheaper than a wrong one (#2880). " +
			"The panic replaces the call, so nothing else is written.",
	})
}
