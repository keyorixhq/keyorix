package store

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedLiveEnv creates a live environments row (seedLiveProjects, in
// dangling_project_role_test.go, does the same for projects). A scoped role grant
// authorizes only when its project and environment rows exist and are not
// soft-deleted (INV-STORE-scoped-grant-needs-live-scope-row), so a fixture that
// grants at environment 9 must create environment 9.
func seedLiveEnv(t *testing.T, db *gorm.DB, envID, projectID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.Environment{ID: envID, ProjectID: projectID, Name: fmt.Sprintf("env-%d", envID)}).Error)
}
