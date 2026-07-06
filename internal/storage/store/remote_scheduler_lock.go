package store

import "context"

// WithSchedulerLock is a confirmed genuine gap (round 119 completeness audit),
// not the "never reached remotely" claim this comment previously made —
// server/main.go starts every background scheduler unconditionally regardless
// of storage.type, so this fails (returning false, not-acquired) on every tick
// of a storage.type: remote deployment too. It is now the sole blocker keeping
// several already-remote-proxied maintenance operations (e.g. #520's
// retention-purge fix) from ever actually running on a schedule there. Tracked
// in docs/security/HARDENING-BACKLOG.md; see remote_unsupported_completeness_test.go.
func (rs *RemoteStorage) WithSchedulerLock(_ context.Context, _ int64, _ func() error) (bool, error) {
	return false, remoteUnsupported("WithSchedulerLock")
}
