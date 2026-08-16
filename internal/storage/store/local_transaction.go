// local_transaction.go — WithTransaction for the local (DB-backed) store.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"gorm.io/gorm"
)

// WithTransaction runs fn inside a single GORM transaction. fn receives a
// transaction-scoped LocalStorage: every mutation it makes is committed together when
// fn returns nil, and rolled back together if fn returns an error (or panics). The
// transaction-scoped store shares the parent's audit-chain, audit-checkpoint, and
// bootstrap mutexes so an audit append, checkpoint write, or bootstrap seed inside
// the transaction still serializes correctly (ADR-029/#339).
func (ls *LocalStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&LocalStorage{db: tx, auditChainMu: ls.auditChainMu, auditCheckpointMu: ls.auditCheckpointMu, bootstrapMu: ls.bootstrapMu})
	})
}
