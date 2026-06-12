package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newProjectMFACore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "needs-mfa", RequireMFA: true}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "open"}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

func reqWithUser(u *UserContext) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	if u != nil {
		r = r.WithContext(context.WithValue(r.Context(), userContextKey, u))
	}
	return r
}

func TestProjectMFABlocked(t *testing.T) {
	cs := newProjectMFACore(t)
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	t.Run("interactive, no MFA, project requires MFA: BLOCKED", func(t *testing.T) {
		assert.True(t, ProjectMFABlocked(reqWithUser(sessionNoMFA), cs, 1))
	})

	t.Run("interactive, no MFA, project does NOT require MFA: allowed", func(t *testing.T) {
		assert.False(t, ProjectMFABlocked(reqWithUser(sessionNoMFA), cs, 2))
	})

	t.Run("interactive WITH MFA: allowed even on MFA-required project", func(t *testing.T) {
		withMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
		assert.False(t, ProjectMFABlocked(reqWithUser(withMFA), cs, 1))
	})

	t.Run("PAT (non-interactive) without MFA: EXEMPT", func(t *testing.T) {
		pat := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: false, MFAEnabled: false}
		assert.False(t, ProjectMFABlocked(reqWithUser(pat), cs, 1), "automation must not be blocked by per-project MFA")
	})

	t.Run("machine identity: EXEMPT", func(t *testing.T) {
		mid := uint(5)
		machine := &UserContext{MachineIdentityID: &mid, ActorType: core.ActorTypeMachine, SessionAuth: false}
		assert.False(t, ProjectMFABlocked(reqWithUser(machine), cs, 1))
	})

	t.Run("global scope (projectID 0): not subject to any project policy", func(t *testing.T) {
		assert.False(t, ProjectMFABlocked(reqWithUser(sessionNoMFA), cs, 0))
	})
}
