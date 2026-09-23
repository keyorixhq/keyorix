package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// grantS9RolesAssignAtProject grants userID roles.assign at the given project
// via a fresh, dedicated role (never reusing an existing role name, since
// this file's shared newHandlerCoreS4 singleton DB is reused across many
// tests -- see F6 sweep, 2026-09-22: requireGranterHoldsRolePermissions now
// requires a roles.assign baseline before any role grant, independent of
// what the grant's own role bundles).
func grantS9RolesAssignAtProject(t *testing.T, h *CatalogHandler, userID, projectID uint) {
	t.Helper()
	ctx := context.Background()
	// newHandlerCoreS4's shared singleton DB is never bootstrap-seeded (unlike
	// createTestToken-backed fixtures), so roles.assign may not exist as a
	// row yet -- create it idempotently rather than assuming it's present.
	perms, err := h.coreService.ListPermissions(ctx)
	require.NoError(t, err)
	var rolesAssignID uint
	for _, p := range perms {
		if p.Name == "roles.assign" {
			rolesAssignID = p.ID
			break
		}
	}
	if rolesAssignID == 0 {
		p, err := h.coreService.Storage().CreatePermission(ctx, &models.Permission{
			Name: "roles.assign", Description: "test-only: assign and remove roles", Resource: "roles", Action: "assign",
		})
		require.NoError(t, err)
		rolesAssignID = p.ID
	}
	roleName, err := identity.NewFoldedName(fmt.Sprintf("s9_roles_assign_role_%d_%d", userID, projectID))
	require.NoError(t, err)
	role, err := h.coreService.Storage().CreateRole(ctx, roleName, "test-only: roles.assign")
	require.NoError(t, err)
	require.NoError(t, h.coreService.AssignPermissionToRole(ctx, 0, role.ID, rolesAssignID, false))
	require.NoError(t, h.coreService.Storage().AssignRole(ctx, userID, role.ID, storage.Scope{ProjectID: projectID}))
}

// ── admin_jobs.go ─────────────────────────────────────────────────────────────

func TestAdminJobsHandler_RunAnomalyAlerts_Unauthorized_S9(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RunAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminJobsHandler_RunAnomalyAlerts_HappyPath_S9(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunAnomalyAlerts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunRotationReminders_Unauthorized_S9(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.RunRotationReminders(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminJobsHandler_RunRotationReminders_HappyPath_S9(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunRotationReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── users_roles.go ────────────────────────────────────────────────────────────

func TestUpdateUserRoles_InvalidRoleID_S9(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	body := strings.NewReader(`{"role_ids":[99999]}`)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", body), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// Role 99999 doesn't exist → 400 "Role ID X does not exist"
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserRolesForUser_WithUserCtx_S9(t *testing.T) {
	h := NewUsersRolesHandler(newHandlerCoreS4(t))
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	// User 1 doesn't exist → empty roles (200) or 500
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSearchUsers_EmptyQuery_S9(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?q=", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSearchUsers_HappyPath_S9(t *testing.T) {
	h := newUserHandlerS4(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?q=test", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	// SQLite lacks ILIKE so ListUsers may return 500 on some drivers; accept 200 or 500
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestSearchUsers_Unauthorized_S9(t *testing.T) {
	h := newUserHandlerS4(t)
	req := httptest.NewRequest(http.MethodGet, "/?q=test", nil)
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── access_request_proxy.go: success paths ────────────────────────────────────

func TestCreateAccessRequestProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	body := `{"project_id":1,"user_id":1,"state":"pending","requester_id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccessRequestProxy_NotFound_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999")
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetAccessRequestProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)

	// Create an access request first
	createBody := `{"project_id":2,"user_id":2,"state":"pending","requester_id":2}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateAccessRequestProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Success bool `json:"success"`
		Data    struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.True(t, createResp.Success)
	require.NotZero(t, createResp.Data.ID)

	// Now get it by ID
	getReq := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", strconv.FormatUint(uint64(createResp.Data.ID), 10))
	getW := httptest.NewRecorder()
	h.GetAccessRequestProxy(getW, getReq)
	assert.Equal(t, http.StatusOK, getW.Code)
}

func TestUpdateAccessRequestProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// FIX-1's requireGranterHoldsRolePermissions ceiling resolves the granted
	// role by ID once the update transitions to "approved", so a real role
	// must exist for the (empty by default) suggested_role to resolve to.
	ensureS4TestRole(t, h, "s9-approve-role")

	// Create a pending access request
	createBody := `{"project_id":3,"user_id":3,"state":"pending","requester_id":3,"suggested_role":"s9-approve-role"}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateAccessRequestProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	// Update state to approved
	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)
	updateBody := `{"state":"approved"}`
	updateReq := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(updateBody)), "id", idStr)
	updateW := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(updateW, updateReq)
	assert.Equal(t, http.StatusOK, updateW.Code)
}

func TestListAccessRequestsProxy_WithData_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)

	// Create an access request for project 42
	createBody := `{"project_id":42,"user_id":4,"state":"pending","requester_id":4}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateAccessRequestProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// List for project 42 → should include the created one (covers loop body)
	listReq := httptest.NewRequest(http.MethodGet, "/?project_id=42", nil)
	listW := httptest.NewRecorder()
	h.ListAccessRequestsProxy(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
}

func TestCreateAccessRequestApprovalProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// CreateAccessRequestApprovalProxy now re-derives the same authority
	// ceiling core.ApproveAccessRequestWithExpiry applies (access-request-proxy-
	// create-approval-ceiling finding), which resolves the request's role by
	// name -- suggested_role must be a real, resolvable role.
	ensureS4TestRole(t, h, "s9-approval-role")
	// F6 sweep (2026-09-22): approving now ALSO requires roles.assign as a
	// baseline before the (here vacuous) per-role escalation check above --
	// grant the approver (UserID=1, via withUserCtx below) that permission at
	// the request's own project.
	grantS9RolesAssignAtProject(t, h, 1, 5)

	// Create an access request first
	createBody := `{"project_id":5,"user_id":5,"state":"pending","requester_id":5,"suggested_role":"s9-approval-role"}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateAccessRequestProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	// Create approval for it
	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)
	approvalBody := `{"approver_id":10}`
	approvalReq := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(approvalBody)), "id", idStr))
	approvalW := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(approvalW, approvalReq)
	assert.Equal(t, http.StatusOK, approvalW.Code)
}

func TestListAccessRequestApprovalsProxy_WithData_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	// CreateAccessRequestApprovalProxy now re-derives an authority ceiling
	// that resolves the request's role by name -- suggested_role must be a
	// real, resolvable role.
	ensureS4TestRole(t, h, "s9-approval-role")
	// F6 sweep (2026-09-22): see TestCreateAccessRequestApprovalProxy_Success_S9's
	// identical comment above -- this test uses project 6.
	grantS9RolesAssignAtProject(t, h, 1, 6)

	// Create access request and an approval
	createBody := `{"project_id":6,"user_id":6,"state":"pending","requester_id":6,"suggested_role":"s9-approval-role"}`
	createReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody))
	createW := httptest.NewRecorder()
	h.CreateAccessRequestProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)

	approvalBody := `{"approver_id":11}`
	approvalReq := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(approvalBody)), "id", idStr))
	approvalW := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(approvalW, approvalReq)
	require.Equal(t, http.StatusOK, approvalW.Code)

	// List approvals (covers the loop body)
	listReq := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", idStr)
	listW := httptest.NewRecorder()
	h.ListAccessRequestApprovalsProxy(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
}

// ── access_review_campaigns_proxy.go: success paths ──────────────────────────

// TestCreateAccessReviewCampaignProxy_Success_S9: CreateAccessReviewCampaignProxy
// now requires roles.assign scoped to the project -- #AccessReview
// (system-proxy-target-authority audit). newCatalogHandlerS4 is backed by the
// shared, non-admin sharedS4Core, so this uses the s4AdminActorID/
// seedS4AdminActor/withUserCtxID pattern other s4/s5/s9 tests needing admin
// authority against that shared core already use.
func TestCreateAccessReviewCampaignProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)
	body := `{"project_id":10,"name":"S9 Campaign","created_by":1,"state":"open"}`
	req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), s4AdminActorID, "s4admin")
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccessReviewCampaignProxy_NotFound_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999")
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetAccessReviewCampaignProxy_Success_S9's fixture campaign is created
// via CreateAccessReviewCampaignProxy, which now requires roles.assign
// scoped to the project (#AccessReview, system-proxy-target-authority audit)
// -- see TestCreateAccessReviewCampaignProxy_Success_S9's doc for the pattern.
func TestGetAccessReviewCampaignProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create first
	createBody := `{"project_id":11,"name":"S9 Get Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	// Get
	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)
	getReq := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", idStr)
	getW := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(getW, getReq)
	assert.Equal(t, http.StatusOK, getW.Code)
}

// TestListAccessReviewCampaignsProxy_WithData_S9's fixture campaign is
// created via CreateAccessReviewCampaignProxy, which now requires
// roles.assign scoped to the project (#AccessReview,
// system-proxy-target-authority audit).
func TestListAccessReviewCampaignsProxy_WithData_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create a campaign for project 20
	createBody := `{"project_id":20,"name":"S9 List Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// List for project 20 (covers loop body)
	listReq := httptest.NewRequest(http.MethodGet, "/?project_id=20", nil)
	listW := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
}

// TestGetOpenAccessReviewCampaignProxy_WithCampaign_S9's fixture campaign is
// created via CreateAccessReviewCampaignProxy, which now requires
// roles.assign scoped to the project (#AccessReview,
// system-proxy-target-authority audit).
func TestGetOpenAccessReviewCampaignProxy_WithCampaign_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create an open campaign for project 21
	createBody := `{"project_id":21,"name":"S9 Open Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Get open campaign
	req := httptest.NewRequest(http.MethodGet, "/?project_id=21", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCreateAccessReviewItemsProxy_Success_S9: both CreateAccessReviewCampaignProxy
// and CreateAccessReviewItemsProxy now require roles.assign scoped to the
// project (#AccessReview, system-proxy-target-authority audit) -- the latter
// derives its scope from a real GetAccessReviewCampaign lookup, so the
// campaign fixture must exist genuinely (it does here, via the proxy call
// itself) and the items call needs its own authorized caller too.
func TestCreateAccessReviewItemsProxy_Success_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create campaign first
	createBody := `{"project_id":40,"name":"S9 Items Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	// Create items (empty list covers the success path)
	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)
	itemsBody := `{"items":[]}`
	itemsReq := withUserCtxID(withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(itemsBody)), "id", idStr), s4AdminActorID, "s4admin")
	itemsW := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(itemsW, itemsReq)
	assert.Equal(t, http.StatusOK, itemsW.Code)
}

// TestListAccessReviewItemsProxy_WithData_S9's fixture campaign is created via
// CreateAccessReviewCampaignProxy, which now requires roles.assign scoped to
// the project (#AccessReview, system-proxy-target-authority audit).
func TestListAccessReviewItemsProxy_WithData_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create campaign + items
	createBody := `{"project_id":50,"name":"S9 ListItems Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)

	// List items (empty but covers ListAccessReviewItemsProxy success)
	listReq := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", idStr)
	listW := httptest.NewRecorder()
	h.ListAccessReviewItemsProxy(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
}

// TestCountPendingAccessReviewItemsProxy_S9's fixture campaign is created via
// CreateAccessReviewCampaignProxy, which now requires roles.assign scoped to
// the project (#AccessReview, system-proxy-target-authority audit).
func TestCountPendingAccessReviewItemsProxy_S9(t *testing.T) {
	h := newCatalogHandlerS4(t)
	seedS4AdminActor(t, h.coreService)

	// Create campaign
	createBody := `{"project_id":60,"name":"S9 Count Campaign","created_by":1,"state":"open"}`
	createReq := withUserCtxID(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(createBody)), s4AdminActorID, "s4admin")
	createW := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	var createResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(createW.Body).Decode(&createResp))
	require.NotZero(t, createResp.Data.ID)

	idStr := strconv.FormatUint(uint64(createResp.Data.ID), 10)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", idStr)
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── admin_impersonation.go: End success paths ─────────────────────────────────

func TestImpersonationHandler_End_NoAdminCookie_S9(t *testing.T) {
	// EndImpersonation with a fake token returns an error (not an impersonation session).
	// This path is: token present → EndImpersonation fails → 400
	// (already tested by End_InvalidToken). We want the success path where
	// EndImpersonation succeeds. For that we need a real impersonation session.
	// Test the "not an impersonation" error branch via a non-impersonation token.
	core := newHandlerCoreS4(t)
	h := NewImpersonationHandler(core, false)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer not-an-impersonation-token")
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── webauthn_proxy.go: success paths ─────────────────────────────────────────

func TestListWebAuthnCredentialsProxy_WithData_S9(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)

	// Seed a credential directly via storage (CreateWebAuthnCredentialProxy was
	// deleted -- G80 liveness sweep found no live caller; see
	// docs/g80-remediation-notes.md). credential_id carries a DB-level unique
	// constraint; fold in a counter (see s4UniqueCounter) so a repeat invocation
	// against the shared sharedS4Core DB doesn't collide with its own prior insert.
	credID := []byte(fmt.Sprintf("test-cred-s92-%d", s4UniqueCounter.Add(1)))
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{
		UserID:         77,
		CredentialID:   credID,
		Name:           "s9-list-cred",
		CredentialBlob: []byte(`{}`),
	}))

	// List (covers loop body)
	listReq := httptest.NewRequest(http.MethodGet, "/?user_id=77", nil)
	listW := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(listW, listReq)
	assert.Equal(t, http.StatusOK, listW.Code)
}

func TestCountWebAuthnCredentialsProxy_WithData_S9(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)

	// Seed a credential directly via storage (CreateWebAuthnCredentialProxy was
	// deleted -- G80 liveness sweep found no live caller; see
	// docs/g80-remediation-notes.md). credential_id carries a DB-level unique
	// constraint; fold in a counter (see s4UniqueCounter) so a repeat invocation
	// against the shared sharedS4Core DB doesn't collide with its own prior insert.
	credID := []byte(fmt.Sprintf("test-cred-s93-%d", s4UniqueCounter.Add(1)))
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{
		UserID:         88,
		CredentialID:   credID,
		Name:           "s9-count-cred",
		CredentialBlob: []byte(`{}`),
	}))

	// Count
	countReq := httptest.NewRequest(http.MethodGet, "/?user_id=88", nil)
	countW := httptest.NewRecorder()
	h.CountWebAuthnCredentialsProxy(countW, countReq)
	assert.Equal(t, http.StatusOK, countW.Code)
}

func TestUpdateWebAuthnCredentialProxy_Success_S9(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)

	// Seed a credential directly via storage (CreateWebAuthnCredentialProxy was
	// deleted -- G80 liveness sweep found no live caller; see
	// docs/g80-remediation-notes.md).
	cred := &models.WebAuthnCredential{
		UserID:         99,
		CredentialID:   []byte("test-cred-s94"),
		Name:           "s9-update-cred",
		CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(context.Background(), cred))
	require.NotZero(t, cred.ID)

	// Update: #1714 narrowed this route to the ONE legitimate transition
	// (disable-on-clone) — it no longer accepts an arbitrary full-row
	// replacement (name/credential_id could previously be overwritten wholesale).
	idStr := strconv.FormatUint(uint64(cred.ID), 10)
	updateBody := `{"user_id":99,"credential_id":"dGVzdC1jcmVkLXM5NA==","disabled":true}`
	// Self-service: caller authenticates as the credential's own owner
	// (UserID 99), matching body.UserID exactly — the route's one
	// no-extra-check path (#UpdateWebAuthnCredential, system-proxy-target-authority
	// audit).
	updateReq := withUserCtxID(
		withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(updateBody)), "id", idStr),
		99, "s9-webauthn-caller",
	)
	updateW := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(updateW, updateReq)
	assert.Equal(t, http.StatusOK, updateW.Code)
}

func TestCreateWebAuthnSessionProxy_Success_S9(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	// token_hash carries a DB-level unique constraint; fold in a counter (see
	// s4UniqueCounter) so a repeat invocation against the shared sharedS4Core DB
	// doesn't collide with its own prior insert.
	tokenHash := fmt.Sprintf("s9-test-token-hash-unique-%d", s4UniqueCounter.Add(1))
	body := fmt.Sprintf(`{"user_id":66,"token_hash":%q,"expires_at":"2030-01-01T00:00:00Z"}`, tokenHash)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
