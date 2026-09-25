// handlers_s31_test.go — broken-DB error-path sweep for proxy endpoints added
// in rounds 119-120 (access-review-campaigns, access-requests, break-glass,
// SoD-policies, setup-tokens, SSO-state, connect-grants, WebAuthn, users-roles).
//
// Each test wires a CatalogHandler / AuthHandler / UsersRolesHandler to a
// closed SQLite DB so every storage call returns an error immediately, driving
// the handler's 500-branch that previous tests missed.
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var s31DBCounter atomic.Int64

func freshCoreBrokenS31(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s31DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s31_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS31AdminMinusCampaigns returns a KeyorixCore with a WORKING role
// system (User/Role/UserRole/... migrated, an admin role assigned to
// UserID=1 so withUserCtx's caller clears the roles.assign authority check
// CreateAccessReviewCampaignProxy now runs ahead of its storage call) but
// deliberately WITHOUT the access_review_campaigns table migrated -- the
// storage-layer CreateAccessReviewCampaign call itself is the thing meant to
// fail here, not the (new) authority check ahead of it.
//
// #AccessReview (system-proxy-target-authority audit): before that authority
// check existed, freshCoreBrokenS31's fully-closed DB connection was enough
// to drive CreateAccessReviewCampaign's own error path (the handler's only
// storage call). Now the authority check runs FIRST and touches storage too
// (role resolution) -- with a closed connection it fails exactly as fail-
// closed as it should, but that reroutes the response to 403
// PERMISSION_DENIED before ever reaching CreateAccessReviewCampaign, so the
// old fixture no longer exercises the code path this test's name claims to
// cover. Splitting "role resolution must work" from "the campaigns table
// must not" isolates the storage failure this test is actually about.
func freshCoreS31AdminMinusCampaigns(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s31DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s31admin_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "s31admin", Email: "s31admin@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS31AdminMinusItems is freshCoreS31AdminMinusCampaigns's sibling for
// CreateAccessReviewItemsProxy: the access_review_campaigns table IS migrated
// (the handler now fetches the campaign first, to scope its own roles.assign
// check, so that lookup must genuinely succeed) but access_review_items is
// deliberately left unmigrated so CreateAccessReviewItems' own storage call
// is what fails.
func freshCoreS31AdminMinusItems(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s31DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s31admin2_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AccessReviewCampaign{},
	))
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "s31admin2", Email: "s31admin2@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// ── CatalogHandler / access_review_campaigns_proxy.go ─────────────────────────

// TestCreateAccessReviewCampaignProxy_DBError_S31 verifies that a genuine
// storage failure inside CreateAccessReviewCampaign itself (not the
// #AccessReview roles.assign authority check ahead of it) surfaces as 500.
// Needs an authorized admin caller (freshCoreS31AdminMinusCampaigns) so the
// new authority check -- which also touches storage for role resolution --
// passes cleanly and the response genuinely reflects the campaigns-table
// storage error, not a fail-closed 403 from a broken role lookup.

// TestCreateAccessReviewItemsProxy_DBError_S31 verifies that a genuine
// storage failure inside CreateAccessReviewItems itself (not the
// #AccessReview roles.assign authority check, and not the campaign lookup
// that check now depends on) surfaces as 500. Needs a real campaign row (the
// handler fetches it first to scope its authority check) and an authorized
// admin caller (freshCoreS31AdminMinusItems) so both of those succeed
// cleanly, isolating the access_review_items-table storage failure this test
// is actually about.

// ── CatalogHandler / access_request_proxy.go ──────────────────────────────────

// ── CatalogHandler / break_glass_proxy.go ─────────────────────────────────────

// TestGetBreakGlassActivationProxy_DBError_S31 was asserting 404 before the G80
// documented-exception fix corrected GetBreakGlassActivation's error wrapping
// (local_break_glass.go): it used to wrap EVERY error, including a genuine
// storage failure, with the same "not found" prefix isNotFoundErr string-
// matches on. A closed/unreachable DB is a real 500, not a 404 — see
// GetMachineIdentityCredentialByID's identical, already-fixed precedent
// (local_machine_credentials.go) for the same bug class.

// ── CatalogHandler / sod_proxy.go ─────────────────────────────────────────────

// #1529: local_sod.go's GetSoDPolicy used to wrap EVERY storage error (not
// just gorm.ErrRecordNotFound) with the "not found" i18n string, so a genuine
// outage like this test's broken DB got mislabeled as 404 -- the same
// pre-existing bug DeleteSoDPolicyProxy_DBError_S31 below already expects 500
// for. Now that GetSoDPolicy distinguishes a real not-found from any other
// error (matching local_alert_escalation.go's established pattern), a broken
// DB correctly surfaces as 500 here too.

// ── AuthHandler / setup_tokens_proxy.go ───────────────────────────────────────

// TestConsumeSetupTokenProxy_DBError_S31 deleted -- #1579 liveness sweep,
// handler removed (no live caller in either topology).

// ── AuthHandler / sso_state_proxy.go ──────────────────────────────────────────

// ── AuthHandler / connect_grants_proxy.go ─────────────────────────────────────

// ── AuthHandler / webauthn_proxy.go ───────────────────────────────────────────

// ── UsersRolesHandler / users_roles.go ────────────────────────────────────────

func TestGetUserRolesForUser_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewUsersRolesHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/users/1/roles", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetUserPermissionsForUser_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewUsersRolesHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/users/1/permissions", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetUserMembershipsForUser_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewUsersRolesHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/users/1/memberships", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateUserRoles_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewUsersRolesHandler(freshCoreBrokenS31(t))
	// Empty role_ids skips the ListRoles DB call and goes directly to SetUserRoles
	body := bytes.NewBufferString(`{"role_ids":[],"project_id":0,"environment_id":0}`)
	r := withChiParamS7(withUserCtxS7(httptest.NewRequest(http.MethodPut, "/api/v1/users/1/roles", body)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
