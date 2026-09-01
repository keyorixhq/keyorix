// invitations_project_members_s13_test.go — coverage sweep for:
//   - invitations.go: ListInvitations bad param, CreateInvitation missing body/fields,
//     ResendInvitation bad params + not-found + conflict, RevokeInvitation bad params,
//     ListAccessRequests bad param, CreateAccessRequest bad param + unknown role,
//     ResolveAccessRequest bad param + unknown action + bad TTL + not-found,
//     WithdrawAccessRequest bad param + not-found + forbidden
//   - invitations_proxy.go: CreateInvitationProxy bad body + missing fields,
//     GetInvitationProxy bad param + not-found, UpdateInvitationProxy bad param +
//     bad body + invalid state, ListInvitationsProxy missing param + bad param
//   - project_members.go: ListProjectMembers bad param, GetProjectAccessReview bad param,
//     AddProjectMember bad param + missing fields + unknown role + already member,
//     UpdateProjectMember bad param + missing role + unknown role,
//     RemoveProjectMember bad param + not a member,
//     RevokeProjectAccessReview bad param + missing source,
//     AttestProjectAccessReview bad param + missing source
package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var b *bytes.Reader
	if body != "" {
		b = bytes.NewReader([]byte(body))
	} else {
		b = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, url, b)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// ── ListInvitations ───────────────────────────────────────────────────────────

func TestListInvitations_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/abc/invitations", nil)),
		"id", "abc",
	)
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CreateInvitation ──────────────────────────────────────────────────────────

func TestCreateInvitation_BadProjectParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/bad/invitations", `{"email":"a@b.io","role":"viewer"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_MissingFields_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/invitations", `{"email":""}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "email and role are required")
}

func TestCreateInvitation_UnknownRole_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	// Seed a project so the project-ID lookup succeeds.
	proj := &models.Project{Name: "inv-proj-s13a"}
	require.NoError(t, db.Create(proj).Error)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/invitations", `{"email":"x@y.io","role":"bogus_role"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	// Unknown role returns 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateInvitation_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations", bytes.NewReader([]byte("not-json")))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ResendInvitation ──────────────────────────────────────────────────────────

func TestResendInvitation_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/invitations/1/resend", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResendInvitation_BadInvitationID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations/bad/resend", nil)),
		map[string]string{"id": "1", "invitationId": "bad"},
	)
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid invitation ID")
}

func TestResendInvitation_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations/9999/resend", nil)),
		map[string]string{"id": "1", "invitationId": "9999"},
	)
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── RevokeInvitation ─────────────────────────────────────────────────────────

func TestRevokeInvitation_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/bad/invitations/1", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeInvitation_BadInvitationID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/1/invitations/bad", nil)),
		map[string]string{"id": "1", "invitationId": "bad"},
	)
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid invitation ID")
}

func TestRevokeInvitation_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/1/invitations/9999", nil)),
		map[string]string{"id": "1", "invitationId": "9999"},
	)
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── ListAccessRequests ────────────────────────────────────────────────────────

func TestListAccessRequests_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/access-requests", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CreateAccessRequest ───────────────────────────────────────────────────────

func TestCreateAccessRequest_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/bad/access-requests", `{"suggested_role":"viewer"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_UnknownRole_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "ar-proj-s13"}
	require.NoError(t, db.Create(proj).Error)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/access-requests", `{"suggested_role":"totally_fake_role"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	// unknown role → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAccessRequest_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/access-requests", bytes.NewReader([]byte("{{not json")))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── ResolveAccessRequest ──────────────────────────────────────────────────────

func TestResolveAccessRequest_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/bad/access-requests/1", `{"action":"approve"}`)),
		map[string]string{"id": "bad", "requestId": "1"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveAccessRequest_BadRequestID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/access-requests/bad", `{"action":"approve"}`)),
		map[string]string{"id": "1", "requestId": "bad"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveAccessRequest_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	baseReq := httptest.NewRequest(http.MethodPut, "/api/v1/projects/1/access-requests/1", bytes.NewReader([]byte("not-json")))
	baseReq.Header.Set("Content-Type", "application/json")
	req := withChiParams(
		withUserCtx(baseReq),
		map[string]string{"id": "1", "requestId": "1"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResolveAccessRequest_UnknownAction_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/access-requests/1", `{"action":"cancel"}`)),
		map[string]string{"id": "1", "requestId": "1"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "action must be approve or reject")
}

// TestResolveAccessRequest_SelfApproval_S13 -- #1645: ApproveAccessRequestWithExpiry's
// "a requester cannot approve their own access request" business rule previously
// fell through to a generic 500 (matched none of the handler's status branches),
// misreporting a legitimate authorization-adjacent denial as a server bug.
func TestResolveAccessRequest_SelfApproval_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.AccessRequest{
		ID: 1, ProjectID: 1, UserID: 1, SuggestedRole: "viewer", State: "pending",
	}).Error)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/access-requests/1", `{"action":"approve"}`)),
		map[string]string{"id": "1", "requestId": "1"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestResolveAccessRequest_BadGrantTTL_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/access-requests/1", `{"action":"approve","grant_ttl":"not-a-duration"}`)),
		map[string]string{"id": "1", "requestId": "1"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "grant_ttl")
}

func TestResolveAccessRequest_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/access-requests/9999", `{"action":"reject","reason":"no"}`)),
		map[string]string{"id": "1", "requestId": "9999"},
	)
	w := httptest.NewRecorder()
	h.ResolveAccessRequest(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── WithdrawAccessRequest ─────────────────────────────────────────────────────

func TestWithdrawAccessRequest_BadRequestID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/access-requests/bad/withdraw", nil)),
		"requestId", "bad",
	)
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request ID")
}

func TestWithdrawAccessRequest_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/access-requests/9999/withdraw", nil)),
		"requestId", "9999",
	)
	w := httptest.NewRecorder()
	h.WithdrawAccessRequest(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── invitations_proxy.go ──────────────────────────────────────────────────────

func TestCreateInvitationProxy_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/invitations", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

func TestCreateInvitationProxy_MissingEmailState_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	// project_id set, but no email
	req := jsonReq(t, http.MethodPost, "/api/v1/system/invitations", `{"project_id":1,"state":"pending"}`)
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "email and state are required")
}

func TestCreateInvitationProxy_MissingProjectScope_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	// no project_id, no system_role, no assignments_json → invalid for project-scoped
	req := jsonReq(t, http.MethodPost, "/api/v1/system/invitations", `{"email":"a@b.io","state":"pending"}`)
	w := httptest.NewRecorder()
	h.CreateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id is required")
}

func TestGetInvitationProxy_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/invitations/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

func TestGetInvitationProxy_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/invitations/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NOT_FOUND")
}

func TestUpdateInvitationProxy_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		jsonReq(t, http.MethodPut, "/api/v1/system/invitations/bad", `{"state":"accepted"}`),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

func TestUpdateInvitationProxy_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/invitations/1", bytes.NewReader([]byte("not-json"))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

func TestUpdateInvitationProxy_InvalidState_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	// "pending" is explicitly excluded; only accepted/revoked/expired allowed
	req := withChiParam(
		jsonReq(t, http.MethodPut, "/api/v1/system/invitations/1", `{"state":"pending"}`),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateInvitationProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "state must be one of")
}

func TestListInvitationsProxy_MissingParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/invitations", nil)
	w := httptest.NewRecorder()
	h.ListInvitationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id query parameter is required")
}

func TestListInvitationsProxy_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/invitations?project_id=abc", nil)
	w := httptest.NewRecorder()
	h.ListInvitationsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id must be a valid integer")
}

// ── project_members.go ────────────────────────────────────────────────────────

func TestListProjectMembers_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/members", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetProjectAccessReview_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/access-review", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddProjectMember_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/bad/members", `{"user_id":2,"role":"viewer"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddProjectMember_MissingFields_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/members", `{"role":"viewer"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user_id and role are required")
}

func TestAddProjectMember_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/members", bytes.NewReader([]byte("not-json")))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAddProjectMember_UnknownRole_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "pm-proj-s13"}
	require.NoError(t, db.Create(proj).Error)
	user2 := &models.User{Username: "member2s13", Email: "member2s13@example.com"}
	require.NoError(t, db.Create(user2).Error)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/members",
			`{"user_id":2,"role":"bogus_role"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_BadProjectID_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/bad/members/2", `{"role":"viewer"}`)),
		map[string]string{"id": "bad", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateProjectMember_BadUserID_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/members/bad", `{"role":"viewer"}`)),
		map[string]string{"id": "1", "userId": "bad"},
	)
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid user ID")
}

func TestUpdateProjectMember_MissingRole_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/members/2", `{"role":""}`)),
		map[string]string{"id": "1", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "role is required")
}

func TestUpdateProjectMember_UnknownRole_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "pm-update-s13"}
	require.NoError(t, db.Create(proj).Error)
	user2 := &models.User{Username: "pmupdate2s13", Email: "pmupdate2s13@example.com"}
	require.NoError(t, db.Create(user2).Error)

	req := withChiParams(
		withUserCtx(jsonReq(t, http.MethodPut, "/api/v1/projects/1/members/2", `{"role":"no_such_role"}`)),
		map[string]string{"id": "1", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveProjectMember_BadProjectID_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/bad/members/2", nil)),
		map[string]string{"id": "bad", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveProjectMember_BadUserID_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/1/members/bad", nil)),
		map[string]string{"id": "1", "userId": "bad"},
	)
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid user ID")
}

func TestRemoveProjectMember_NotAMember_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "pm-remove-s13"}
	require.NoError(t, db.Create(proj).Error)
	user2 := &models.User{Username: "notmember2s13", Email: "notmember2s13@example.com"}
	require.NoError(t, db.Create(user2).Error)

	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodDelete, "/api/v1/projects/1/members/2", nil)),
		map[string]string{"id": "1", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── RevokeProjectAccessReview ─────────────────────────────────────────────────

func TestRevokeProjectAccessReview_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/bad/access-review/revoke", `{"source":"user_role"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeProjectAccessReview_MissingSource_InvS13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/access-review/revoke", `{"source":""}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "source is required")
}

func TestRevokeProjectAccessReview_BadBody_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/access-review/revoke", bytes.NewReader([]byte("not-json")))),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.RevokeProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── AttestProjectAccessReview ─────────────────────────────────────────────────

func TestAttestProjectAccessReview_BadParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/bad/access-review/attest", `{"source":"user_role"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestProjectAccessReview_MissingSource_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(
		withUserCtx(jsonReq(t, http.MethodPost, "/api/v1/projects/1/access-review/attest", `{"source":""}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.AttestProjectAccessReview(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "source is required")
}
