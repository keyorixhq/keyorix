package store

import "context"

// WithAuditCheckpointLock is server-side only — WriteAuditCheckpoint (and its
// three triggers: scheduler, HTTP, gRPC) always runs against LocalStorage inside
// the server process; the CLI's `keyorix audit checkpoint` goes through the HTTP
// endpoint rather than calling the core method directly against RemoteStorage. A
// remote caller reaching this would get no real cross-process guarantee anyway
// (there is no shared advisory lock to take over HTTP), so this fails closed
// rather than silently running fn unserialized.
func (rs *RemoteStorage) WithAuditCheckpointLock(_ context.Context, _ func() error) error {
	return remoteUnsupported("WithAuditCheckpointLock")
}
