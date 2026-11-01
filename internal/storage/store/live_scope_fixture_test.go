package store

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedLiveProjects creates a live projects row for each id, and seedLiveEnv a live
// environments row. A scoped role grant authorizes only when its project (and
// environment) row exists and is not soft-deleted (INV-STORE-scoped-grant-needs-live-scope-row),
// so a fixture that grants at project 5 must create project 5.
func seedLiveProjects(t *testing.T, db *gorm.DB, ids ...uint) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: fmt.Sprintf("proj-%d", id)}).Error)
	}
}

func seedLiveEnv(t *testing.T, db *gorm.DB, envID, projectID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.Environment{ID: envID, ProjectID: projectID, Name: fmt.Sprintf("env-%d", envID)}).Error)
}
