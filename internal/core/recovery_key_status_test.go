// recovery_key_status_test.go — coverage for GetRecoveryKeyStatus (F6,
// recovery-key visibility).
package core

import (
	"context"
	"testing"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newRecoveryKeyStatusTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RecoveryKeyRecord{}))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// TestGetRecoveryKeyStatus_NotConfigured verifies a fresh install (no
// recovery key generated yet) reports Configured=false and never errors —
// the ordinary, expected state on a brand-new deployment.
func TestGetRecoveryKeyStatus_NotConfigured(t *testing.T) {
	c, _ := newRecoveryKeyStatusTestCore(t)
	status, err := c.GetRecoveryKeyStatus(context.Background())
	require.NoError(t, err)
	assert.False(t, status.Configured)
	assert.Zero(t, status.Generation)
}

// TestGetRecoveryKeyStatus_Configured verifies a generated key reports
// Configured=true with its generation, and never carries the key/hash
// itself (the RecoveryKeyStatus type has no field for it at all).
func TestGetRecoveryKeyStatus_Configured(t *testing.T) {
	c, db := newRecoveryKeyStatusTestCore(t)
	require.NoError(t, db.Create(&models.RecoveryKeyRecord{
		ID: 1, KeyHash: "not-a-real-hash", KeyVersion: 3,
	}).Error)

	status, err := c.GetRecoveryKeyStatus(context.Background())
	require.NoError(t, err)
	assert.True(t, status.Configured)
	assert.Equal(t, 3, status.Generation)
}
