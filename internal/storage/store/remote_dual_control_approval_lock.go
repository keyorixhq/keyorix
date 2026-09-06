package store

import "context"

// WithDualControlApprovalLock is a no-op passthrough over RemoteStorage,
// mirroring WithTransaction's own reasoning (remote_transaction.go) and
// WithSoDGrantLock's above: ApproveAccessRequestWithExpiry is an ordinary
// caller reachable through a RemoteStorage-backed KeyorixCore (storage.type:
// remote, ADR-049), unlike WithBootstrapLock's genuinely-unreachable case.
// There is no shared advisory lock to take over HTTP; the hub this
// RemoteStorage talks to enforces the real guarantee against its own
// concurrent writers via its own LocalStorage-backed
// WithDualControlApprovalLock.
func (rs *RemoteStorage) WithDualControlApprovalLock(_ context.Context, fn func() error) error {
	return fn()
}
