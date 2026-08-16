package store

import "context"

// WithBootstrapLock is server-side only — BootstrapSystem always runs against
// LocalStorage inside the server process (the HTTP POST /system/init handler is
// its only caller); nothing calls it against RemoteStorage. A remote caller
// reaching this would get no real cross-process guarantee anyway (there is no
// shared advisory lock to take over HTTP), so this fails closed rather than
// silently running fn unserialized.
func (rs *RemoteStorage) WithBootstrapLock(_ context.Context, _ func() error) error {
	return remoteUnsupported("WithBootstrapLock")
}
