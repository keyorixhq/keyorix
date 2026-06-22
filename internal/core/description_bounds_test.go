package core

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestValidateDescription(t *testing.T) {
	assert.NoError(t, validateDescription(""))
	assert.NoError(t, validateDescription(strings.Repeat("x", maxSecretDescriptionLen)))
	assert.Error(t, validateDescription(strings.Repeat("x", maxSecretDescriptionLen+1)))
	// Whitespace is trimmed before measuring.
	assert.NoError(t, validateDescription("  "+strings.Repeat("x", maxSecretDescriptionLen-2)+"  "))
}

// The cap is enforced at the governance create/update choke points (covers HTTP+CLI).
func TestCreateProject_RejectsOverlongDescription(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.Group{}, &models.AuditEvent{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	_, err = c.CreateProject(ctx, "p", strings.Repeat("x", maxSecretDescriptionLen+1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "description exceeds")

	_, err = c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "g", Description: strings.Repeat("x", maxSecretDescriptionLen+1)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "description exceeds")

	// A normal description is accepted.
	_, err = c.CreateProject(ctx, "ok", "a reasonable description")
	require.NoError(t, err)
}
