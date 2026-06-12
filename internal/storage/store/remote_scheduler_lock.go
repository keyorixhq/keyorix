package store

import "context"

// WithSchedulerLock is server-side only — background schedulers run on the server
// (LocalStorage), never the remote client. A remote caller never reaches this, so
// it conservatively reports "not acquired" and runs nothing.
func (rs *RemoteStorage) WithSchedulerLock(_ context.Context, _ int64, _ func() error) (bool, error) {
	return false, remoteUnsupported("WithSchedulerLock")
}
