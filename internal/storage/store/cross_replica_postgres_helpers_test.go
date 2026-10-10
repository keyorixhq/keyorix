// cross_replica_postgres_helpers_test.go — shared setup for this package's
// cross-replica Postgres tests (PERF-3): two independent store.LocalStorage
// instances, own *gorm.DB pool each, sharing one real Postgres schema
// migrated through the production entry point. Mirrors
// internal/core/postgres_contention_helpers_test.go's own reasoning for why
// each "replica" needs its own connection/instance, not a shared one.
package store_test

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	storagefactory "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var rbacCrossReplicaSchemaSeq atomic.Int64

// newRBACCrossReplicaPair returns two independent store.LocalStorage instances
// (own *gorm.DB pool, own in-process cache each) sharing one real Postgres
// schema, migrated through the production path. t.Cleanup drops the schema.
func newRBACCrossReplicaPair(t *testing.T) (*store.LocalStorage, *store.LocalStorage) {
	t.Helper()
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping cross-replica Postgres test")
	}
	schema := fmt.Sprintf("perf3_crcache_%d_%d", os.Getpid(), rbacCrossReplicaSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		cleaner, cerr := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		if cerr == nil {
			_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})
	targetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)

	_, err = storagefactory.NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: targetDSN}},
	})
	require.NoError(t, err)

	openReplica := func() *store.LocalStorage {
		db, oerr := gorm.Open(postgres.Open(targetDSN), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, oerr)
		sqlDB, derr := db.DB()
		require.NoError(t, derr)
		sqlDB.SetMaxOpenConns(2)
		sqlDB.SetMaxIdleConns(1)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return store.NewLocalStorage(db)
	}
	return openReplica(), openReplica()
}
