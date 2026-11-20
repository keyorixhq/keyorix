package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestBulkSecretRoutes_InactiveActorIsForbidden: core refuses a suspended acting
// account at bulk-rename, bulk-suspend and resume-all (requireActorActive, #4159,
// bound in #4522). Each route must answer that refusal 403, not 500.
func TestBulkSecretRoutes_InactiveActorIsForbidden(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.User{}, &models.Role{}, &models.UserRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	ensureActiveActorUser(t, c.Storage(), 1)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("is_active", false).Error)
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	routes := []struct {
		name string
		path string
		body string
		call func(http.ResponseWriter, *http.Request)
	}{
		{"bulk-rename", "/api/v1/projects/1/secrets/bulk-rename", `{"renames":[{"id":5,"new_name":"X"}]}`, h.BulkRenameSecrets},
		{"bulk-suspend", "/api/v1/projects/1/secrets/suspend-all", `{"reason":"r"}`, h.SuspendProjectSecrets},
		{"resume-all", "/api/v1/projects/1/secrets/resume-all", `{}`, h.ResumeProjectSecrets},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, rt.path, strings.NewReader(rt.body))), "id", "1")
			w := httptest.NewRecorder()
			rt.call(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		})
	}
}
