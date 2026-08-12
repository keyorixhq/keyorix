// handlers_s13_project_test.go — sprint-13 coverage sweep targeting:
//   - project_members.go: ListProjectMembers, GetProjectAccessReview,
//     UpdateProjectMember (no-user-ctx / happy-path branches not yet covered)
//   - project_memberships.go: ListProjectMemberships, InviteMember,
//     TransitionMembership, membershipActionState
//   - project_memberships_proxy.go: CreateMembershipProxy, GetMembershipProxy,
//     UpdateMembershipProxy, ListMembershipsProxy, GetActiveMembershipProxy,
//     ListStaleInvitedMembershipsProxy, ListUserMembershipsProxy,
//     CountMembershipsByUsersProxy (missing error/validation branches)
//   - project_catalog_proxy.go: ListProjectsProxy, ListProjectsWithCountsProxy,
//     GetProjectProxy, UpdateProjectProxy, DeleteProjectProxy,
//     DeleteProjectIfEmptyProxy, RestoreProjectProxy, ListProjectMembersProxy
//   - project_hygiene.go: ProjectHygiene (bad-param / no-auth)
//   - projects_suspend.go: SuspendProjectSecrets, ResumeProjectSecrets
//     (bad-param / no-auth error paths)
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newSecretHandlerProjS13 wraps freshCoreS12 in a SecretHandler (no admin seeded).
func newSecretHandlerProjS13(t *testing.T) *SecretHandler {
	t.Helper()
	h, err := NewSecretHandler(freshCoreS12(t))
	require.NoError(t, err)
	return h
}

// newCatalogHandlerProjS13 wraps freshCoreS12 in a CatalogHandler (no admin seeded).
func newCatalogHandlerProjS13(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(freshCoreS12(t))
}

// ── project_members.go — branches NOT already in invitations_project_members_s13_test.go ──

// TestListProjectMembers_HappyPath_S13 — valid project ID → 200.
func TestListProjectMembers_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmembers", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetProjectAccessReview_HappyPath_S13 — valid project ID → 200.
func TestGetProjectAccessReview_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13accessreview", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRevokeProjectAccessReview_NoUserCtx_S13 — no user context → 401.
func TestRevokeProjectAccessReview_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"source":"manual","principal_type":"user","principal_id":1,"role_id":1}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	// no user context injected
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUpdateProjectMember_NoUserCtx_S13 — no user context → 401.
func TestUpdateProjectMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"role":"viewer"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestUpdateProjectMember_BadJSON_S13 — malformed JSON body → 400.
func TestUpdateProjectMember_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad"))),
		map[string]string{"id": "1", "userId": "2"})
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveProjectMember_NoUserCtx_S13 — no user context → 401.
func TestRemoveProjectMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "1", "userId": "2"})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── project_memberships.go ───────────────────────────────────────────────────

// TestListProjectMemberships_BadID_S13 — non-numeric project ID → 400.
func TestListProjectMemberships_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProjectMemberships_HappyPath_S13 — valid project ID, no stale filter → 200.
func TestListProjectMemberships_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmemships", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListProjectMemberships_Stale_S13 — ?stale=true path, empty result is fine → 200.
func TestListProjectMemberships_Stale_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmemships-stale", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/?stale=true", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestInviteMember_BadID_S13 — non-numeric project ID → 400.
func TestInviteMember_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":1,"role":"viewer"}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "notnum")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInviteMember_NoUserCtx_S13 — no actor context → 401.
func TestInviteMember_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":1,"role":"viewer"}`
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestInviteMember_BadJSON_S13 — malformed JSON → 400.
func TestInviteMember_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))), "id", "1")
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInviteMember_MissingFields_S13 — missing user_id/role → 400.
func TestInviteMember_MissingFields_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"user_id":0,"role":""}`
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))), "id", "1")
	w := httptest.NewRecorder()
	h.InviteMember(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_BadProjectID_S13 — non-numeric project ID → 400.
func TestTransitionMembership_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "notnum", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_BadMembershipID_S13 — non-numeric membershipId → 400.
func TestTransitionMembership_BadMembershipID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "membershipId": "notnum"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_NoUserCtx_S13 — no actor context → 401.
func TestTransitionMembership_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"activate"}`
	r := withChiParams(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)),
		map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestTransitionMembership_BadJSON_S13 — malformed JSON → 400.
func TestTransitionMembership_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad"))),
		map[string]string{"id": "1", "membershipId": "1"})
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMembership_InvalidAction_S13 — unknown action → 400.
func TestTransitionMembership_InvalidAction_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"action":"teleport"}`
	r := withChiParams(withUserCtx(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))),
		map[string]string{"id": "1", "membershipId": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembership(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMembershipActionState_AllActions_S13 — unit-test the action→state mapper.
func TestMembershipActionState_AllActions_S13(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		action string
		want   string
		ok     bool
	}{
		{"verify", "identity_verified", true},
		{"provision", "provisioned", true},
		{"activate", "active", true},
		{"revoke", "revoked", true},
		{"unknown", "", false},
		{"", "", false},
	} {
		tc := tc
		t.Run(tc.action, func(t *testing.T) {
			t.Parallel()
			got, ok := membershipActionState(tc.action)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// ── project_memberships_proxy.go ─────────────────────────────────────────────

// TestCreateMembershipProxy_BadJSON_S13 — malformed JSON body → 400.
func TestCreateMembershipProxy_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMembershipProxy_MissingFields_S13 — zero project_id/user_id → 400.
func TestCreateMembershipProxy_MissingFields_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"project_id":0,"user_id":0,"role":"","state":""}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMembershipProxy_BadID_S13 — non-numeric membership ID → 400.
func TestGetMembershipProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.GetMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateMembershipProxy_BadID_S13 — non-numeric membership ID → 400.
func TestUpdateMembershipProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"project_id":1,"user_id":1,"role":"viewer","state":"active"}`
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "notnum")
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateMembershipProxy_BadJSON_S13 — malformed JSON body → 400.
func TestUpdateMembershipProxy_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.UpdateMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetActiveMembershipProxy_MissingParams_S13 — no project_id / user_id → 400.
func TestGetActiveMembershipProxy_MissingParams_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetActiveMembershipProxy_BadProjectID_S13 — invalid project_id → 400.
func TestGetActiveMembershipProxy_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?project_id=bad&user_id=1", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetActiveMembershipProxy_BadUserID_S13 — invalid user_id → 400.
func TestGetActiveMembershipProxy_BadUserID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?project_id=1&user_id=bad", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetActiveMembershipProxy_NotFound_S13 — valid IDs but no membership → 404.
func TestGetActiveMembershipProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?project_id=99999&user_id=99999", nil)
	w := httptest.NewRecorder()
	h.GetActiveMembershipProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestListStaleInvitedMembershipsProxy_MissingBefore_S13 — no before param → 400.
func TestListStaleInvitedMembershipsProxy_MissingBefore_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListStaleInvitedMembershipsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListStaleInvitedMembershipsProxy_BadBefore_S13 — invalid timestamp → 400.
func TestListStaleInvitedMembershipsProxy_BadBefore_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?before=not-a-time", nil)
	w := httptest.NewRecorder()
	h.ListStaleInvitedMembershipsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListUserMembershipsProxy_BadUserID_S13 — non-numeric userID → 400.
func TestListUserMembershipsProxy_BadUserID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "userID", "notnum")
	w := httptest.NewRecorder()
	h.ListUserMembershipsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountMembershipsByUsersProxy_MissingParam_S13 — no user_ids → 400.
func TestCountMembershipsByUsersProxy_MissingParam_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountMembershipsByUsersProxy_BadUserIDs_S13 — non-numeric value in list → 400.
func TestCountMembershipsByUsersProxy_BadUserIDs_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?user_ids=1,bad,3", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountMembershipsByUsersProxy_HappyPath_S13 — valid user_ids → 200.
func TestCountMembershipsByUsersProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?user_ids=1,2,3", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── project_catalog_proxy.go ─────────────────────────────────────────────────

// TestListProjectsProxy_HappyPath_S13 — empty DB → 200 with empty list.
func TestListProjectsProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectsProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListProjectsWithCountsProxy_HappyPath_S13 — no include_deleted → 200.
func TestListProjectsWithCountsProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListProjectsWithCountsProxy_IncludeDeleted_S13 — include_deleted=true → 200.
func TestListProjectsWithCountsProxy_IncludeDeleted_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := httptest.NewRequest(http.MethodGet, "/?include_deleted=true", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetProjectProxy_BadID_S13 — non-numeric id → 400.
func TestGetProjectProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetProjectProxy_NotFound_S13 — non-existent id → 404.
func TestGetProjectProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "99999")
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetProjectProxy_HappyPath_S13 — existing project → 200.
func TestGetProjectProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13getprojproxy", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.GetProjectProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUpdateProjectProxy_BadID_S13 — non-numeric id → 400.
func TestUpdateProjectProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	body := `{"name":"test","description":""}`
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "notnum")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateProjectProxy_BadJSON_S13 — malformed JSON → 400.
func TestUpdateProjectProxy_BadJSON_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1")
	r.ContentLength = 4
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateProjectProxy_HappyPath_S13 — update an existing project → 200.
func TestUpdateProjectProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13updateprojproxy", "")
	require.NoError(t, err)

	body := fmt.Sprintf(`{"id":%d,"name":"s13updateprojproxy-new","description":"updated"}`, proj.ID)
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestUpdateProjectProxy_PreservesTimestamps_G80 is the #G80 regression:
// projectProxyWire.toModel() previously dropped CreatedAt/UpdatedAt/DeletedAt
// even though the wire struct (and its response-leg constructor) carry them,
// so every proxied update silently zeroed the project's CreatedAt.
func TestUpdateProjectProxy_PreservesTimestamps_G80(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13g80timestamps", "")
	require.NoError(t, err)
	require.False(t, proj.CreatedAt.IsZero(), "fixture project must have a real CreatedAt to prove it survives")

	body := fmt.Sprintf(`{"id":%d,"name":"s13g80timestamps-new","description":"updated","created_at":%q}`,
		proj.ID, proj.CreatedAt.Format(time.RFC3339Nano))
	r := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	updated, err := cs.Storage().GetProject(context.Background(), proj.ID)
	require.NoError(t, err)
	assert.False(t, updated.CreatedAt.IsZero(), "CreatedAt must not be zeroed by the proxy update")
	assert.WithinDuration(t, proj.CreatedAt, updated.CreatedAt, time.Second)
}

// TestDeleteProjectProxy_BadID_S13 — non-numeric id → 400.
func TestDeleteProjectProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.DeleteProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteProjectProxy_NotFound_S13 — non-existent id → 404.
func TestDeleteProjectProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "99999")
	w := httptest.NewRecorder()
	h.DeleteProjectProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteProjectProxy_HappyPath_S13 — existing project → 200.
func TestDeleteProjectProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13delproj", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.DeleteProjectProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestDeleteProjectIfEmptyProxy_BadID_S13 — non-numeric id → 400.
func TestDeleteProjectIfEmptyProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteProjectIfEmptyProxy_NotFound_S13 — non-existent id → 404.
func TestDeleteProjectIfEmptyProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "99999")
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteProjectIfEmptyProxy_HappyPath_S13 — empty project → 200.
func TestDeleteProjectIfEmptyProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13delifempty", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.DeleteProjectIfEmptyProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRestoreProjectProxy_BadID_S13 — non-numeric id → 400.
func TestRestoreProjectProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.RestoreProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRestoreProjectProxy_NotFound_S13 — non-existent / non-deleted id → 404.
func TestRestoreProjectProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "99999")
	w := httptest.NewRecorder()
	h.RestoreProjectProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestListProjectMembersProxy_BadID_S13 — non-numeric id → 400.
func TestListProjectMembersProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newCatalogHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notnum")
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProjectMembersProxy_HappyPath_S13 — valid project → 200.
func TestListProjectMembersProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "s13listmemproxy", "")
	require.NoError(t, err)

	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── project_hygiene.go ───────────────────────────────────────────────────────

// TestProjectHygiene_NoUserCtx_S13 — no user context → 401.
func TestProjectHygiene_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProjectHygiene_BadID_S13 — non-numeric project ID → 400.
func TestProjectHygiene_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "notnum")
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestProjectHygiene_HappyPath_S13 — valid project with optional query params → 200.
func TestProjectHygiene_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13hygiene", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/?unused_days=30&expiring_days=7&stale_days=90", nil)),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ProjectHygiene(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── projects_suspend.go ──────────────────────────────────────────────────────

// TestSuspendProjectSecrets_NoUserCtx_S13 — no user context → 401.
func TestSuspendProjectSecrets_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`)), "id", "1")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSuspendProjectSecrets_BadID_S13 — non-numeric project ID → 400.
func TestSuspendProjectSecrets_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))), "id", "notnum")
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSuspendProjectSecrets_HappyPath_S13 — valid project ID → 200.
func TestSuspendProjectSecrets_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13suspend", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"reason":"incident"}`))),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.SuspendProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResumeProjectSecrets_NoUserCtx_S13 — no user context → 401.
func TestResumeProjectSecrets_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestResumeProjectSecrets_BadID_S13 — non-numeric project ID → 400.
func TestResumeProjectSecrets_BadID_S13(t *testing.T) {
	t.Parallel()
	h := newSecretHandlerProjS13(t)
	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)), "id", "notnum")
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestResumeProjectSecrets_HappyPath_S13 — valid project ID → 200.
func TestResumeProjectSecrets_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	proj, err := cs.CreateProject(context.Background(), "s13resume", "")
	require.NoError(t, err)

	r := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		"id", fmt.Sprintf("%d", proj.ID))
	w := httptest.NewRecorder()
	h.ResumeProjectSecrets(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
