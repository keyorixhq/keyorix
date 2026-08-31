package store

import "context"

// WithNamedLock is a plain passthrough for RemoteStorage: the caller (a CLI/node
// running storage.type: remote) is not the process holding the real database
// connection — the hub it proxies to is — so there is no local advisory lock this
// process could meaningfully take. This does not weaken #1646's fix: the mutation
// paths WithNamedLock protects (SoD grant checks, last-admin guards) still run their
// checks against the hub's own storage when proxied, and a deployment where the
// races this closes actually matter (multiple replicas sharing one real Postgres) is
// exactly the LocalStorage-backed topology WithNamedLock's advisory lock covers.
func (rs *RemoteStorage) WithNamedLock(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
