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
