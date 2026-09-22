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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
func TestCreateAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request against a fully-migrated
	// admin-backed core (access_review_campaigns table present) must
	// succeed -- isolating the 500 below to the missing-table storage
	// failure specifically, not the roles.assign authority check ahead of
	// it or some other cause. clientSafe() redacts the response body to a
	// fixed generic string, so this before/after delta is the available
	// proof (no message text to assert on).
	baselineCS, _ := freshCoreS12WithAdmin(t)
	baselineH := NewCatalogHandler(baselineCS)
	baselineBody := bytes.NewBufferString(`{"project_id":1,"name":"Test Campaign","state":"open","created_by":1}`)
	baselineR := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns", baselineBody))
	baselineW := httptest.NewRecorder()
	baselineH.CreateAccessReviewCampaignProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (campaigns table present) must succeed: %s", baselineW.Body.String())

	h := NewCatalogHandler(freshCoreS31AdminMinusCampaigns(t))
	body := bytes.NewBufferString(`{"project_id":1,"name":"Test Campaign","state":"open","created_by":1}`)
	r := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns", body))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, r)
	// local storage wraps First() errors as "ErrorNotFound", so isNotFoundErr triggers 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListAccessReviewCampaignsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetOpenAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/open?project_id=1", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetLatestClosedAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/latest-closed?project_id=1", nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCreateAccessReviewItemsProxy_DBError_S31 verifies that a genuine
// storage failure inside CreateAccessReviewItems itself (not the
// #AccessReview roles.assign authority check, and not the campaign lookup
// that check now depends on) surfaces as 500. Needs a real campaign row (the
// handler fetches it first to scope its authority check) and an authorized
// admin caller (freshCoreS31AdminMinusItems) so both of those succeed
// cleanly, isolating the access_review_items-table storage failure this test
// is actually about.
func TestCreateAccessReviewItemsProxy_DBError_S31(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request/fixture shape against a
	// fully-migrated admin-backed core (access_review_items table present)
	// must succeed -- isolating the 500 below to the missing-table storage
	// failure specifically, not the roles.assign authority check or the
	// campaign lookup ahead of it. clientSafe() redacts the response body
	// to a fixed generic string, so this before/after delta is the
	// available proof.
	baselineCS, baselineDB := freshCoreS12WithAdmin(t)
	baselineH := NewCatalogHandler(baselineCS)
	baselineCampaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "S31 DBError Items Baseline", State: "open", CreatedBy: 1}
	require.NoError(t, baselineDB.Create(baselineCampaign).Error)
	baselineBody := bytes.NewBufferString(`{"items":[{"principal_type":"user","principal_id":1,"decision":"pending"}]}`)
	baselineR := withUserCtx(withChiParamS7(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", baselineCampaign.ID), baselineBody),
		"id", fmt.Sprintf("%d", baselineCampaign.ID),
	))
	baselineW := httptest.NewRecorder()
	baselineH.CreateAccessReviewItemsProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (items table present) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS31AdminMinusItems(t)
	h := NewCatalogHandler(cs)
	campaign := &models.AccessReviewCampaign{ProjectID: 1, Name: "S31 DBError Items", State: "open", CreatedBy: 1}
	require.NoError(t, db.Create(campaign).Error)
	body := bytes.NewBufferString(`{"items":[{"principal_type":"user","principal_id":1,"decision":"pending"}]}`)
	r := withUserCtx(withChiParamS7(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", campaign.ID), body),
		"id", fmt.Sprintf("%d", campaign.ID),
	))
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccessReviewItemsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/1/items", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewItemsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountPendingAccessReviewItemsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/1/items/pending-count", nil), "id", "1")
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAccessReviewItemProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-review-campaigns/items/1", nil), "itemID", "1")
	w := httptest.NewRecorder()
	h.GetAccessReviewItemProxy(w, r)
	// GetAccessReviewItem (local_access_review_campaigns.go) used to wrap
	// EVERY error, including a closed/unreachable DB, as "not found" -- fixed
	// to match GetAccessRequest/GetMachineIdentityCredentialByID's
	// already-established pattern, so a real storage failure is now
	// correctly a 500, not a 404.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateAccessReviewItemProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	// principal_id (5) != withUserCtx's authenticated caller (UserID=1) so
	// ARC-005 passes; broken storage then returns 500. G80 documented-
	// exception re-verification sweep (2026-08-25): the self-certification
	// check is now anchored to the authenticated caller, not decided_by.
	body := bytes.NewBufferString(`{"principal_id":5,"principal_type":"user","decision":"attest"}`)
	r := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/access-review-campaigns/items/1", body), "itemID", "1"))
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / access_request_proxy.go ──────────────────────────────────

func TestCreateAccessRequestProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"project_id":1,"user_id":2,"state":"pending","reason":"need access"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/access-requests", body)
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetAccessRequestProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-requests/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, r)
	// GetAccessRequest (local_invitations.go) used to wrap EVERY error,
	// including a closed/unreachable DB, as "not found" regardless of cause
	// -- fixed to match GetMachineIdentityCredentialByID's already-established
	// pattern (distinguish genuine gorm.ErrRecordNotFound from everything
	// else), so a real storage failure is now correctly a 500, not a 404.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateAccessRequestProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"state":"approved","project_id":1,"user_id":1}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/access-requests/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, r)
	// UpdateAccessRequestProxy re-fetches the row first (AR-001); GetAccessRequest's
	// error wrapping was fixed (see TestGetAccessRequestProxy_DBError_S31 above),
	// so a real storage failure now correctly surfaces as 500, not 404.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccessRequestsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/access-requests?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateAccessRequestApprovalProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"approver_id":2}`)
	r := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/access-requests/1/approvals", body), "id", "1"))
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccessRequestApprovalsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/access-requests/1/approvals", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessRequestApprovalsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / break_glass_proxy.go ─────────────────────────────────────

// TestGetBreakGlassActivationProxy_DBError_S31 was asserting 404 before the G80
// documented-exception fix corrected GetBreakGlassActivation's error wrapping
// (local_break_glass.go): it used to wrap EVERY error, including a genuine
// storage failure, with the same "not found" prefix isNotFoundErr string-
// matches on. A closed/unreachable DB is a real 500, not a 404 — see
// GetMachineIdentityCredentialByID's identical, already-fixed precedent
// (local_machine_credentials.go) for the same bug class.
func TestGetBreakGlassActivationProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/break-glass/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListBreakGlassActivationsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/break-glass?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeBreakGlassActivationProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(fmt.Sprintf(`{"revoked_by":1,"revoked_at":"%s"}`, time.Now().UTC().Format(time.RFC3339)))
	r := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/break-glass/1/revoke", body), "id", "1"))
	w := httptest.NewRecorder()
	h.RevokeBreakGlassActivationProxy(w, r)
	// broken DB returns generic error (not ErrBreakGlassNotActive), so 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / sod_proxy.go ─────────────────────────────────────────────

func TestCreateSoDPolicyProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"name":"no-dual","permission_a":"secret:read","permission_b":"secret:write"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/sod-policies", body)
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// #1529: local_sod.go's GetSoDPolicy used to wrap EVERY storage error (not
// just gorm.ErrRecordNotFound) with the "not found" i18n string, so a genuine
// outage like this test's broken DB got mislabeled as 404 -- the same
// pre-existing bug DeleteSoDPolicyProxy_DBError_S31 below already expects 500
// for. Now that GetSoDPolicy distinguishes a real not-found from any other
// error (matching local_alert_escalation.go's established pattern), a broken
// DB correctly surfaces as 500 here too.
func TestGetSoDPolicyProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/sod-policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteSoDPolicyProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/system/sod-policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler / setup_tokens_proxy.go ───────────────────────────────────────

func TestCreateSetupTokenProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(fmt.Sprintf(`{"token_hash":"abc123","purpose":"account_setup","subject_email":"x@example.com","subject_user_id":1,"state":"active","expires_at":%q,"created_by":1,"created_at":"2024-01-01T00:00:00Z"}`, time.Now().Add(24*time.Hour).Format(time.RFC3339)))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/setup-tokens", body)
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, r)
	// #G79: CreateSetupTokenProxy now looks up subject_user_id (GetUser) before
	// ever reaching CreateSetupToken, and fails closed on ANY error from that
	// lookup (including a broken-DB storage error, indistinguishable here from
	// a genuine "no such user") — so this never reaches the 500 path this test
	// originally exercised.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSetupTokenByHashProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/setup-tokens/by-hash/abc123", nil), "hash", "abc123")
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSupersedeSetupTokensProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"purpose":"invite","subject_email":"x@example.com"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/setup-tokens/supersede", body)
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestConsumeSetupTokenProxy_DBError_S31 deleted -- #1579 liveness sweep,
// handler removed (no live caller in either topology).

func TestExpireSetupTokenProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/setup-tokens/1/expire", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ExpireSetupTokenProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountSetupTokensSinceProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/setup-tokens/count?purpose=invite&subject_email=x@example.com&since=2024-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler / sso_state_proxy.go ──────────────────────────────────────────

func TestCreateSSOLoginStateProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"state":"randomstate","nonce":"randomnonce","provider":"oidc","return_to":"/","expires_at":"2030-01-01T00:00:00Z","created_at":"2024-01-01T00:00:00Z"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/sso-state", body)
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestConsumeSSOLoginStateProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	// use a state value that won't be treated as "not found" by the broken DB error
	body := bytes.NewBufferString(`{"state":"somestate"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/sso-state/consume", body)
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler / connect_grants_proxy.go ─────────────────────────────────────

func TestListConnectRefGrantsByConnectorProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/connect-grants/by-connector/github", nil), "connector", "github")
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsByConnectorProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler / webauthn_proxy.go ───────────────────────────────────────────

func TestListWebAuthnCredentialsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials?user_id=1", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetWebAuthnCredentialByCredIDProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	credIDBase64 := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials/lookup?user_id=1&credential_id="+credIDBase64, nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateWebAuthnCredentialProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	// #1714: disabled:true is required to reach the storage-touching path at
	// all (anything else is rejected before any lookup, so it would never
	// observe the broken DB).
	body := bytes.NewBufferString(`{"user_id":1,"credential_id":"AQIDBA==","disabled":true}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/credentials/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountWebAuthnCredentialsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials/count?user_id=1", nil)
	w := httptest.NewRecorder()
	h.CountWebAuthnCredentialsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateWebAuthnSessionProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"user_id":1,"token_hash":"hash123","purpose":"login","data":"AQIDBA==","expires_at":"2030-01-01T00:00:00Z","created_at":"2024-01-01T00:00:00Z"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions", body)
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

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
