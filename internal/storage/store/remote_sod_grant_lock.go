package store

import "context"

// WithSoDGrantLock is a no-op passthrough over RemoteStorage, mirroring
// WithTransaction's own reasoning (remote_transaction.go): unlike
// WithBootstrapLock (which fails closed because BootstrapSystem never runs
// against RemoteStorage at all), a SoD-gated grant path IS reachable here —
// storage.type: remote lets a CLI process construct a KeyorixCore directly
// against a RemoteStorage-backed hub (ADR-049), and AssignUserRole and
// siblings are ordinary callers with no guard excluding that mode. There is
// no shared advisory lock to take over HTTP, so this cannot provide the same
// cross-replica guarantee LocalStorage's implementation does; failing closed
// here would only break that legitimate caller without closing any gap (a
// single remote CLI invocation has no concurrent sibling to race against on
// the client side, and the hub it talks to enforces its own locking against
// ITS OWN concurrent writers via its own LocalStorage-backed WithSoDGrantLock).
func (rs *RemoteStorage) WithSoDGrantLock(_ context.Context, fn func() error) error {
	return fn()
}
