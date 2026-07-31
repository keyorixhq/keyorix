package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Rotation-policy CRUD must be audited (create/update/delete) — previously these
// wrote nothing, completing the governance-audit gap alongside roles and groups.
func TestRotationPolicyCRUDAudit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RotationPolicy{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	ctx := context.Background()

	count := func(eventType string) int64 {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		return n
	}

	pid := uint(1)
	p, err := c.CreateRotationPolicy(ctx, 9, &CreateRotationPolicyRequest{
		Name: "90-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 90, AlertDaysBefore: 7, CreatedBy: "admin",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count(EventRotationPolicyCreated))

	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventRotationPolicyCreated).First(&ev).Error)
	require.NotNil(t, ev.UserID)
	assert.Equal(t, uint(9), *ev.UserID, "acting admin recorded")

	_, err = c.UpdateRotationPolicy(ctx, 9, &UpdateRotationPolicyRequest{
		ID: p.ID, Name: "60-day", IntervalDays: 60, AlertDaysBefore: 7, IsActive: true,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count(EventRotationPolicyUpdated))

	require.NoError(t, c.DeleteRotationPolicy(ctx, 9, p.ID))
	assert.Equal(t, int64(1), count(EventRotationPolicyDeleted))
}
