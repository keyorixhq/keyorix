package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

// erroringProjectStorage wraps a real Storage but makes GetProject fail with a
// non-"not found" error (a transient storage failure), to exercise the
// genuine fail-closed path without a nonexistent-project "not found" (a
// different, deliberately non-blocking case — see
// TestProjectMFABlocked_NotFoundDoesNotBlock).
type erroringProjectStorage struct {
	corestorage.Storage
}

func (erroringProjectStorage) GetProject(context.Context, uint) (*models.Project, error) {
	return nil, fmt.Errorf("connection reset by peer")
}

// TestProjectMFABlocked_FailsClosedOnLookupError is #G17: a genuine
// ProjectRequiresMFA lookup error (a transient storage failure, distinct from
// "project not found") used to fall through to "not blocked" (`err == nil &&
// req` is false on any error), silently treating an interactive session
// without a second factor as MFA-compliant regardless of the project's real
// policy. It must now deny.
func TestProjectMFABlocked_FailsClosedOnLookupError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	cs := core.NewKeyorixCore(erroringProjectStorage{store.NewLocalStorage(db)})
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	assert.True(t, ProjectMFABlocked(reqWithUser(sessionNoMFA), cs, 1),
		"a genuine ProjectRequiresMFA lookup error must deny, not silently allow")
}

// TestProjectMFABlocked_NotFoundDoesNotBlock is #G17's necessary carve-out:
// ProjectMFABlocked only runs after the caller's scope was already
// permission-checked (finishScopedPermissionRequest only reaches here on
// allowed==true), so a nonexistent project is not an MFA-policy question — it
// must not block, so the handler's own existence check produces the real
// 404/403 instead of a misleading "MFA required" response.
func TestProjectMFABlocked_NotFoundDoesNotBlock(t *testing.T) {
	cs := newProjectMFACore(t)
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	assert.False(t, ProjectMFABlocked(reqWithUser(sessionNoMFA), cs, 999),
		"a nonexistent project must not be blocked by the MFA gate")
}

// TestProjectsMFABlocked is #G17: an aggregate endpoint whose response spans
// several projects must be blocked if ANY of them requires MFA the caller's
// session lacks, even though every individual project ID is passed to the same
// underlying ProjectMFABlocked check that a single-project endpoint uses.
func TestProjectsMFABlocked(t *testing.T) {
	cs := newProjectMFACore(t)
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	t.Run("one of several projects requires MFA: BLOCKED", func(t *testing.T) {
		assert.True(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, []uint{2, 1}))
	})

	t.Run("none of the projects require MFA: allowed", func(t *testing.T) {
		assert.False(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, []uint{2}))
	})

	t.Run("empty set: allowed", func(t *testing.T) {
		assert.False(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, nil))
	})

	t.Run("session WITH MFA: allowed even when a project requires it", func(t *testing.T) {
		withMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true}
		assert.False(t, ProjectsMFABlocked(reqWithUser(withMFA), cs, []uint{1, 2}))
	})
}
