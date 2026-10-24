package main

// shutdown_flush_test.go — #3377: the graceful-shutdown path must write the
// secret-read denial summary rows that are still open at SIGTERM, not only the
// last-used stamps.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestShutdown_FlushesOpenSecretReadDenialSummary(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SystemMetadata{},
		&models.SecretNode{}, &models.User{}, &models.Group{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))

	refuse := func() {
		ctx, note := core.WithSecretReadDenialNote(context.Background(), core.SecretReadPathRESTGet)
		c.RecordNotedSecretReadDenial(ctx, note,
			core.SecretReadDenialActor{UserID: 1, Username: "u1", IP: "10.0.0.9"},
			core.SecretReadDenialTarget{SecretID: 42}, core.SecretReadDeniedForbidden)
	}
	const n = 5
	for range n {
		refuse()
	}
	count := func() int64 {
		var rows int64
		require.NoError(t, db.Model(&models.AuditEvent{}).
			Where("event_type = ? AND success = ?", "secret.read", false).Count(&rows).Error)
		return rows
	}
	require.EqualValues(t, 1, count(), "only the first refusal of the window is written before shutdown")

	flushSecretReadDenialsOnShutdown(c)

	assert.EqualValues(t, 2, count(), "shutdown must write the open window's summary row (the other refusals)")
}
