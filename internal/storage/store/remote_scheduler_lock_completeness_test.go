package store

// This file registers remote_scheduler_lock.go's intentionally-permanent
// remoteUnsupported stubs into remoteUnsupportedAllowlist (declared in
// remote_unsupported_completeness_test.go). See that file's NEW FEATURE
// PATTERN doc comment — new entries belong in a feature-scoped file like this
// one, not in the shared registry.

func init() {
	addRemoteUnsupported(map[string]remoteUnsupportedEntry{
		"TryAcquireSchedulerLock": {statusIntentional,
			"#1480: server-only -- server/scheduler_run.go calls storage.WithSchedulerLock " +
				"on every scheduler tick, and ADR-083's validateRemoteStorageNotServer rejects " +
				"storage.type: remote for a scheduler-only process too (server/main.go always " +
				"starts background schedulers regardless of server.http/grpc.enabled), so this " +
				"is never reached against RemoteStorage in any real deployment. Its only real " +
				"caller, repo-wide, was its own /system proxy handler, AcquireSchedulerLockProxy " +
				"(server/http/handlers/scheduler_lock_proxy.go), now removed."},
		"ReleaseSchedulerLock": {statusIntentional,
			"#1480: same server-only reasoning as TryAcquireSchedulerLock above. Its only real " +
				"caller, repo-wide, was its own /system proxy handler, ReleaseSchedulerLockProxy " +
				"(server/http/handlers/scheduler_lock_proxy.go), now removed."},
		"WithSchedulerLock": {statusIntentional,
			"#1480: same server-only reasoning as TryAcquireSchedulerLock/ReleaseSchedulerLock " +
				"above -- RemoteStorage's own WithSchedulerLock is never reached in any real " +
				"deployment. No dedicated /system proxy route ever backed this one (it wraps " +
				"TryAcquireSchedulerLock/ReleaseSchedulerLock, both now stubs)."},
	})
}
