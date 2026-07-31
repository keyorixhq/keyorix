package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func setupSCIMTest(t *testing.T) (*SCIMHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Session{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	return NewSCIMHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

// withID attaches a chi route param so chi.URLParam("id") resolves in the handler.
func withID(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func decodeSCIM(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
	return m
}

func TestSCIM_ProvisionGetListDeactivateDelete(t *testing.T) {
	h, db := setupSCIMTest(t)

	// Create: an email-style userName derives an alphanumeric username and echoes externalId.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@corp.com","externalId":"okta-123","displayName":"Alice","active":true}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeSCIM(t, w)
	assert.Equal(t, "alice@corp.com", created["userName"])
	assert.Equal(t, "okta-123", created["externalId"])
	assert.Equal(t, true, created["active"])
	id, _ := created["id"].(string)
	require.NotEmpty(t, id)

	// The stored user has a derived alphanumeric username and pending_first_login state.
	var u models.User
	require.NoError(t, db.Where("external_id = ?", "okta-123").First(&u).Error)
	assert.Equal(t, "alice", u.Username)
	assert.Equal(t, core.AccountPendingFirstLogin, u.AccountState)
	assert.NotEmpty(t, u.PasswordHash, "a random (unusable) password is set")

	// Get.
	w = httptest.NewRecorder()
	h.GetUser(w, withID(httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+id, nil), id))
	require.Equal(t, http.StatusOK, w.Code)

	// List with a userName filter returns exactly the one match.
	w = httptest.NewRecorder()
	h.ListUsers(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "alice@corp.com"`), nil))
	require.Equal(t, http.StatusOK, w.Code)
	list := decodeSCIM(t, w)
	assert.Equal(t, float64(1), list["totalResults"])

	// PATCH active=false deactivates the account. IsActive=false blocks login; the
	// existing pending_first_login (restricted) state is PRESERVED, not overwritten to
	// deprovisioned, so a later reactivation can restore it rather than silently
	// clearing the first-login requirement. Only an already-'active' account moves to
	// the deprovisioned state.
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	w = httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+id, bytes.NewReader([]byte(patch))), id))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, false, decodeSCIM(t, w)["active"])

	var suspended models.User
	require.NoError(t, db.Where("external_id = ?", "okta-123").First(&suspended).Error)
	assert.Equal(t, core.AccountPendingFirstLogin, suspended.AccountState, "a restricted state is preserved across SCIM deactivation")
	assert.False(t, suspended.IsActive, "deactivation blocks login via IsActive")

	// DELETE → 204 and the user is soft-deleted.
	w = httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+id, nil), id))
	require.Equal(t, http.StatusNoContent, w.Code)
	var count int64
	require.NoError(t, db.Model(&models.User{}).Where("external_id = ?", "okta-123").Count(&count).Error)
	assert.Equal(t, int64(0), count, "soft-deleted (excluded from default scope)")
}

func TestSCIM_CreateRequiresUserName(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(`{"displayName":"x"}`))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_DuplicateConflict(t *testing.T) {
	h, _ := setupSCIMTest(t)
	body := `{"userName":"bob@corp.com","externalId":"e1"}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code)
	w = httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestSCIM_CannotRewriteNativeAdminEmail pins #120: a SCIM PUT (ReplaceUser) took an
// arbitrary numeric id straight off the URL with no check that SCIM actually
// provisioned it, so a valid (e.g. provisioning-only) SCIM bearer token could rewrite
// a NATIVE admin's email to a fresh attacker-controlled address — the existing
// same-email-collision guard only blocks an address already in use — and then claim
// the account via SSO/SAML email-fallback resolution. The fix refuses ReplaceUser/
// PatchUser/DeleteUser on any id that isn't SCIM-managed (no stored externalId).
func TestSCIM_CannotRewriteNativeAdminEmail(t *testing.T) {
	h, db := setupSCIMTest(t)
	// A native admin: created directly (no externalId), exactly like the classic
	// bootstrap/admin-console account this attack targets.
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "admin", Email: "admin@corp.com", DisplayName: "Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	body := `{"userName":"attacker@evil.com","emails":[{"value":"attacker@evil.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "PUT on a non-SCIM-managed id must be refused")

	// The admin's email must be untouched.
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "admin@corp.com", u.Email, "a native account's email must survive an attempted SCIM rewrite")

	// PATCH and DELETE on the same non-SCIM-managed id must likewise be refused.
	w = httptest.NewRecorder()
	h.PatchUser(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/1", bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"active","value":false}]}`))), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "PATCH on a non-SCIM-managed id must be refused")

	w = httptest.NewRecorder()
	h.DeleteUser(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/1", nil), "1"))
	assert.Equal(t, http.StatusNotFound, w.Code, "DELETE on a non-SCIM-managed id must be refused")

	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, u.IsActive, "the native admin must remain untouched by every SCIM mutation attempt")
}

// TestSCIM_ReplaceUserAllowsGenuinelyManagedAccount is the positive control: the
// normal SCIM lifecycle (an account SCIM itself provisioned) is unaffected.
func TestSCIM_ReplaceUserAllowsGenuinelyManagedAccount(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "bob", Email: "bob@corp.com", DisplayName: "Bob",
		IsActive: true, AccountState: core.AccountActive, ExternalID: "okta|bob",
	}).Error)

	body := `{"userName":"bob@corp.com","displayName":"Bob Updated","emails":[{"value":"bob@corp.com","primary":true}]}`
	w := httptest.NewRecorder()
	h.ReplaceUser(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Users/1", bytes.NewReader([]byte(body))), "1"))
	require.Equal(t, http.StatusOK, w.Code)

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.Equal(t, "Bob Updated", u.DisplayName)
}

// TestSCIM_ListFilterDoesNotLeakNativeAccount pins the "List adoption" half of
// #120: a userName-filter query (the IdP's reconciliation lookup) must not surface a
// NATIVE account by email match — doing so would leak its numeric SCIM resource id
// to any SCIM client, the ID a follow-up PUT/DELETE would otherwise need to target.
func TestSCIM_ListFilterDoesNotLeakNativeAccount(t *testing.T) {
	h, db := setupSCIMTest(t)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "admin", Email: "admin@corp.com", DisplayName: "Admin",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)

	req := httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=userName+eq+"admin@corp.com"`, nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	resp := decodeSCIM(t, w)
	resources, _ := resp["Resources"].([]interface{})
	assert.Empty(t, resources, "a filter match against a native (non-SCIM-managed) account must not be returned")
}

func TestSCIM_ServiceProviderConfig(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.GetServiceProviderConfig(w, httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "scim+json")
	cfg := decodeSCIM(t, w)
	assert.NotNil(t, cfg["patch"])
}
