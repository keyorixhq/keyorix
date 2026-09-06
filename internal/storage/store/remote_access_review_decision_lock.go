package store

import "context"

// WithAccessReviewDecisionLock is a no-op passthrough over RemoteStorage,
// mirroring WithTransaction's own reasoning (remote_transaction.go) and
// WithSoDGrantLock's above: DecideAccessReviewItem is an ordinary caller
// reachable through a RemoteStorage-backed KeyorixCore (storage.type: remote,
// ADR-049), unlike WithBootstrapLock's genuinely-unreachable case. There is no
// shared advisory lock to take over HTTP; the hub this RemoteStorage talks to
// enforces the real guarantee against its own concurrent writers via its own
// LocalStorage-backed WithAccessReviewDecisionLock.
func (rs *RemoteStorage) WithAccessReviewDecisionLock(_ context.Context, fn func() error) error {
	return fn()
}
