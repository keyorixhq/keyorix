// remote_transaction.go — WithTransaction for the remote (HTTP-backed) store.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// WithTransaction runs fn directly against this store. There is no client-side
// transaction to open over HTTP — each remote API call is already atomic server-side,
// and the server applies its own transaction for any multi-step mutation behind a
// single endpoint. fn therefore sees the same (non-transactional) store; callers that
// need a true multi-statement transaction must drive the local store.
func (rs *RemoteStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return fn(rs)
}
