package store

import (
	"context"
	"time"
)

// WithSchedulerLock/TryAcquireSchedulerLock/ReleaseSchedulerLock are not
// supported in remote storage (#1480). They used to be real, DB-backed HTTP
// implementations (#530): server/scheduler_run.go calls
// storage.WithSchedulerLock on every scheduler tick, and that call used to be
// reachable under storage.type: remote if a "downstream Keyorix server"
// relayed the scheduler tick to an upstream. That topology cannot exist
// (ADR-083: validateRemoteStorageNotServer explicitly rejects storage.type:
// remote for a scheduler-only process too, not just one with HTTP/gRPC
// enabled — server/main.go always starts its background schedulers
// regardless of either flag). Every scheduler tick therefore always runs
// against whatever real storage backend the server was actually configured
// with; RemoteStorage's own WithSchedulerLock is never reached in any real
// deployment. Converted to stubs alongside their now-dead /system routes
// (AcquireSchedulerLockProxy/ReleaseSchedulerLockProxy,
// server/http/handlers/scheduler_lock_proxy.go, now removed).
func (rs *RemoteStorage) WithSchedulerLock(_ context.Context, _ int64, _ func() error) (bool, error) {
	return false, remoteUnsupported("WithSchedulerLock")
}

// TryAcquireSchedulerLock is not supported in remote storage — see the
// package doc above.
func (rs *RemoteStorage) TryAcquireSchedulerLock(_ context.Context, _ int64, _ string, _ time.Duration) (bool, error) {
	return false, remoteUnsupported("TryAcquireSchedulerLock")
}

// ReleaseSchedulerLock is not supported in remote storage — see the package
// doc above.
func (rs *RemoteStorage) ReleaseSchedulerLock(_ context.Context, _ int64, _ string) error {
	return remoteUnsupported("ReleaseSchedulerLock")
}
