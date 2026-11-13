// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// #3968: the panic kind of the post-verdict owner read on /auth/refresh. Same
	// decided outcome as the error row (post_auth_refresh_getuser): RefreshSession
	// recovers the panic into the read's error path (refreshStorageCall), so it is
	// ErrStorageReadUnavailable, answered 503, and the slot stays counted.
	registerOracleAByDesign("post_auth_refresh_getuser_panic", oracleAByDesignError{
		op:     "REST POST /auth/refresh",
		method: "GetUser",
		kind:   faultstorage.KindPanic,
		nth:    1,
		tables: []string{"LoginAttempt"},
		designComment: "internal/core/auth.go RefreshSession: GetUser runs through refreshStorageCall, " +
			"which turns its panic into an error, so the panic takes the error " +
			"row's path: post-verdict ErrStorageReadUnavailable, not ErrRefreshNotEvaluated; " +
			"server/http/handlers/auth.go RefreshToken answers it 503 and keeps the per-IP slot",
		provingTest: "server/http/handlers/TestRefresh_StoragePanicSlotPolicy " +
			"(every storage call refresh makes, panic kind, through middleware.Recovery: slot kept, 503); " +
			"internal/core/TestRefreshSession_PostVerdictPanicIsNotEvaluatedOnlyBeforeTheVerdict",
		why: "The token matched a live session and the owner read panicked. Recovered into the error path, the " +
			"refresh is refused 503 + Retry-After and keeps the LoginAttempt slot it reserved, exactly as for the " +
			"read's error: returning it would make a valid token cheaper than a wrong one (#2880). The read " +
			"writes nothing, so the kept LoginAttempt row is the only diff.",
	})
}
