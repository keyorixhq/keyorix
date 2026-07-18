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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

func TestCreateAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"project_id":1,"name":"Test Campaign","state":"open","created_by":1}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns", body)
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

func TestUpdateAccessReviewCampaignProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"project_id":1,"name":"Test","state":"open","created_by":1}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/access-review-campaigns/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewCampaignProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateAccessReviewItemsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"items":[{"user_id":1,"role":"viewer","decision":"pending","reviewed_by":0}]}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns/1/items", body), "id", "1")
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
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAccessReviewItemProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"user_id":1,"role":"viewer","decision":"approved","reviewed_by":2}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/access-review-campaigns/items/1", body), "itemID", "1")
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
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAccessRequestProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"state":"approved","project_id":1,"user_id":1}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/access-requests/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, r)
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
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/access-requests/1/approvals", body), "id", "1")
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

func TestGetBreakGlassActivationProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/break-glass/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetBreakGlassActivationProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListBreakGlassActivationsProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/break-glass?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListBreakGlassActivationsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateBreakGlassActivationProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(`{"project_id":1,"activated_by":1,"state":"active"}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/break-glass/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateBreakGlassActivationProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeBreakGlassActivationProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	body := bytes.NewBufferString(fmt.Sprintf(`{"revoked_by":1,"revoked_at":"%s"}`, time.Now().UTC().Format(time.RFC3339)))
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/break-glass/1/revoke", body), "id", "1")
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

func TestGetSoDPolicyProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS31(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/sod-policies/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
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
	body := bytes.NewBufferString(`{"token_hash":"abc123","purpose":"invite","subject_email":"x@example.com","state":"active","expires_at":"2030-01-01T00:00:00Z","created_by":1,"created_at":"2024-01-01T00:00:00Z"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/setup-tokens", body)
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
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

func TestConsumeSetupTokenProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(fmt.Sprintf(`{"consumed_at":"%s"}`, time.Now().UTC().Format(time.RFC3339)))
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/setup-tokens/1/consume", body), "id", "1")
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

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

func TestCreateConnectRefGrantProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"role_id":1,"connector":"github","ref_prefix":"refs/heads/main"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/connect-grants", body)
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler / webauthn_proxy.go ───────────────────────────────────────────

func TestCreateWebAuthnCredentialProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"user_id":1,"credential_id":"AQIDBA==","name":"YubiKey","credential_blob":"AQIDBA==","created_at":"2024-01-01T00:00:00Z"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/credentials", body)
	w := httptest.NewRecorder()
	h.CreateWebAuthnCredentialProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

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
	body := bytes.NewBufferString(`{"user_id":1,"credential_id":"AQIDBA==","name":"YubiKey","credential_blob":"AQIDBA==","created_at":"2024-01-01T00:00:00Z"}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/credentials/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteWebAuthnCredentialProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	r := withChiParams2_S22(httptest.NewRequest(http.MethodDelete, "/api/v1/system/webauthn/users/1/credentials/1", nil), "userId", "1", "id", "1")
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredentialProxy(w, r)
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

func TestSetUserWebAuthnEnabledProxy_DBError_S31(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS31(t), false)
	body := bytes.NewBufferString(`{"enabled":true}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/users/1/webauthn-enabled", body), "userId", "1")
	w := httptest.NewRecorder()
	h.SetUserWebAuthnEnabledProxy(w, r)
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
