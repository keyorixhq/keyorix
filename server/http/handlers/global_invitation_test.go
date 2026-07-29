package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupGlobalInvitationTest(t *testing.T) (*CatalogHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.UserRole{}, &models.Role{}, &models.Project{},
		&models.ProjectInvitation{}, &models.SetupToken{}, &models.AuditEvent{},
		// AuthorizePrincipal (the invite ceiling) resolves group-inherited roles too.
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "system_auditor"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Project{Name: "default"}).Error)
	// The acting user (withUserCtx → UserID 1) is a global super_admin, so it holds
	// roles.assign everywhere and passes the invite privilege ceiling. A non-admin actor
	// is exercised separately in the ceiling test below.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "testuser", Email: "testuser@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 100, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 100, ProjectID: 0}).Error)
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func postGlobalInvite(t *testing.T, h *CatalogHandler, jsonBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader([]byte(jsonBody))))
	w := httptest.NewRecorder()
	h.CreateGlobalInvitation(w, req)
	return w
}

func TestCreateGlobalInvitation(t *testing.T) {
	h, db := setupGlobalInvitationTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	t.Run("creates a global invitation with system role + project assignments", func(t *testing.T) {
		body := `{"email":"carol@acme.io","role":"system_auditor","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postGlobalInvite(t, h, body)
		// 201 even though the setup link can't be delivered in test (no base_url) —
		// the invitation is still persisted.
		require.Equal(t, http.StatusCreated, w.Code)

		var inv models.ProjectInvitation
		require.NoError(t, db.Where("email = ?", "carol@acme.io").First(&inv).Error)
		assert.Equal(t, uint(0), inv.ProjectID) // global
		assert.Equal(t, "system_auditor", inv.SystemRole)
		assert.Contains(t, inv.AssignmentsJSON, "project_developer")
		assert.Equal(t, core.InvitationPending, inv.State)
	})

	t.Run("missing email rejects with 400", func(t *testing.T) {
		w := postGlobalInvite(t, h, `{"role":"system_viewer"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unknown system role rejects with 400 and creates no invitation", func(t *testing.T) {
		w := postGlobalInvite(t, h, `{"email":"x@y.io","role":"nope_role"}`)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "x@y.io").Count(&n).Error)
		assert.Equal(t, int64(0), n)
	})

	t.Run("unknown project role rejects with 400", func(t *testing.T) {
		body := `{"email":"z@y.io","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"bogus"}]}`
		w := postGlobalInvite(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ADR-022: a configured domain allowlist rejects an invite to a disallowed
// domain with 403, and creates no invitation row.
func TestCreateGlobalInvitation_RejectsDisallowedDomain(t *testing.T) {
	h, db := setupGlobalInvitationTest(t)
	h.coreService.SetMembershipDomainAllowlist([]string{"acme.io"})

	t.Run("disallowed domain rejects with 403", func(t *testing.T) {
		w := postGlobalInvite(t, h, `{"email":"carol@evil.example"}`)
		assert.Equal(t, http.StatusForbidden, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "carol@evil.example").Count(&n).Error)
		assert.Equal(t, int64(0), n)
	})

	t.Run("allowlisted domain still succeeds", func(t *testing.T) {
		w := postGlobalInvite(t, h, `{"email":"dave@acme.io"}`)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

// The invite privilege ceiling: a non-admin actor (holds users.write via the route gate
// but NOT roles.assign) cannot invite with a system role or a project role — otherwise
// an onboarding manager could invite themselves as system_admin and own the install.
func TestCreateGlobalInvitation_EnforcesAssignCeiling(t *testing.T) {
	h, db := setupGlobalInvitationTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)
	require.NoError(t, db.Create(&models.Role{Name: "system_admin"}).Error)

	// Strip the actor's admin authority — user 1 now holds no role-granting power.
	require.NoError(t, db.Where("user_id = ?", 1).Delete(&models.UserRole{}).Error)

	t.Run("inviting a system role without roles.assign → 403", func(t *testing.T) {
		w := postGlobalInvite(t, h, `{"email":"a@b.io","role":"system_admin"}`)
		assert.Equal(t, http.StatusForbidden, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.ProjectInvitation{}).Where("email = ?", "a@b.io").Count(&n).Error)
		assert.Equal(t, int64(0), n, "no invitation is created when the ceiling refuses")
	})

	t.Run("inviting a project role without roles.assign in that project → 403", func(t *testing.T) {
		body := `{"email":"c@d.io","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postGlobalInvite(t, h, body)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("inviting the default baseline (no role) is still allowed", func(t *testing.T) {
		// An empty role defaults to system_viewer (the minimal baseline), which is not a
		// privilege grant, so users.write alone suffices — mirrors CreateUser.
		w := postGlobalInvite(t, h, `{"email":"e@f.io"}`)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}
