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

func newProjectMFATestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func boolPtr(b bool) *bool { return &b }

func TestProjectMFA_ToggleAndQuery(t *testing.T) {
	c, _ := newProjectMFATestCore(t)
	ctx := context.Background()

	// Default: a project does not require MFA.
	req, err := c.ProjectRequiresMFA(ctx, 1)
	require.NoError(t, err)
	assert.False(t, req)

	// Enable per-project MFA via UpdateProject.
	p, err := c.UpdateProject(ctx, 1, "alpha", "", boolPtr(true))
	require.NoError(t, err)
	assert.True(t, p.RequireMFA)
	req, _ = c.ProjectRequiresMFA(ctx, 1)
	assert.True(t, req)

	// A nil requireMFA leaves the flag unchanged (backward-compatible update).
	p, err = c.UpdateProject(ctx, 1, "alpha-renamed", "desc", nil)
	require.NoError(t, err)
	assert.True(t, p.RequireMFA, "nil must not clear the flag")
	assert.Equal(t, "alpha-renamed", p.Name)

	// Disable it again.
	p, err = c.UpdateProject(ctx, 1, "alpha-renamed", "desc", boolPtr(false))
	require.NoError(t, err)
	assert.False(t, p.RequireMFA)
}

func TestProjectMFA_ToggleIsAudited(t *testing.T) {
	c, db := newProjectMFATestCore(t)
	ctx := context.Background()

	_, err := c.UpdateProject(ctx, 1, "alpha", "", boolPtr(true))
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", "project.mfa_requirement_enabled").Count(&count).Error)
	assert.Equal(t, int64(1), count)

	// A no-op (already-enabled) update writes no new audit row.
	_, err = c.UpdateProject(ctx, 1, "alpha", "", boolPtr(true))
	require.NoError(t, err)
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", "project.mfa_requirement_enabled").Count(&count).Error)
	assert.Equal(t, int64(1), count, "an unchanged flag must not re-audit")
}

func TestProjectMFA_MissingProject(t *testing.T) {
	c, _ := newProjectMFATestCore(t)
	_, err := c.ProjectRequiresMFA(context.Background(), 999)
	require.Error(t, err)
}
