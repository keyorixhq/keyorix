package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestSecretTotalReadsCount_IsServedByACoveringIndex: total_reads (core.SecretTotalReads)
// is an unbounded COUNT over a secret's lifetime read history, run on every single-secret
// GET including each value read. With only (secret_node_id, access_time) it needed a heap
// lookup per row to check action and got slower with every read. (secret_node_id, action)
// answers it from the index alone. EXPLAINs the statement production code issued
// (captured from gorm). It does not check Postgres plans (see
// TestAnomalyQueries_UseTheirIndexes); the index is created on both dialects by the same
// migration (TestCompanionIndexes_CreatedOnUpgrade).
func TestSecretTotalReadsCount_IsServedByACoveringIndex(t *testing.T) {
	cap := &anomalySQLCapture{Interface: logger.Discard}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: cap})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretAccessLog{}))
	ls := NewLocalStorage(db)

	_, err = ls.CountSecretReadsBySecretIDs(context.Background(), []uint{1}, time.Time{})
	require.NoError(t, err)

	plan := explainSQLite(t, db, cap.find(t, "COUNT(*)", "secret_access_logs", "action ="))
	require.Contains(t, plan, "COVERING INDEX idx_secret_access_logs_secret_action",
		"the lifetime read count must be answered from (secret_node_id, action) alone; plan: %s", plan)
}
