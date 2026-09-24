// openapi_contract_pr3_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 3 (rbac, group, invite) added response schemas
// for. Each test below drives the real handler through a happy path and calls
// contracttest.AssertOpenAPIResponse so the operation moves from "pending" to
// genuinely enforced -- see CLAUDE.md's "a mechanism must be validated against a
// failure that actually happened" and openapi_contract_pr2_test.go's identical
// precedent. Each test is self-contained (its own fixture), not grafted onto an
// existing test.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractPR3_ListGroups(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.Group{Name: "contract-pr3-group", Description: "d"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil))
	w := httptest.NewRecorder()
	h.ListGroups(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_CreateGroup(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"name": "contract-pr3-create-group"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR3_GetGroup(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	g := &models.Group{Name: "contract-pr3-get-group"}
	require.NoError(t, db.Create(g).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1", nil),
		"id", fmt.Sprintf("%d", g.ID),
	))
	w := httptest.NewRecorder()
	h.GetGroup(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_UpdateGroup(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	g := &models.Group{Name: "contract-pr3-update-group"}
	require.NoError(t, db.Create(g).Error)

	body, _ := json.Marshal(map[string]any{"description": "updated"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/groups/1", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", g.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_GetGroupMembers(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	g := &models.Group{Name: "contract-pr3-members-group"}
	require.NoError(t, db.Create(g).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/members", nil),
		"id", fmt.Sprintf("%d", g.ID),
	))
	w := httptest.NewRecorder()
	h.GetGroupMembers(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_AddGroupMember(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	g := &models.Group{Name: "contract-pr3-add-member-group"}
	require.NoError(t, db.Create(g).Error)
	u := &models.User{Username: "contract-pr3-member", Email: "contract-pr3-member@example.test", DisplayName: "Member"}
	require.NoError(t, db.Create(u).Error)

	body, _ := json.Marshal(map[string]any{"user_id": u.ID})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/members", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", g.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AddGroupMember(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_GetGroupRoles(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	g := &models.Group{Name: "contract-pr3-group-roles"}
	require.NoError(t, db.Create(g).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/groups/1/roles", nil),
		"id", fmt.Sprintf("%d", g.ID),
	))
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_AssignRoleToGroup(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	g := &models.Group{Name: "contract-pr3-assign-role-group"}
	require.NoError(t, db.Create(g).Error)
	role := &models.Role{Name: "contract-pr3-group-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{"role_id": role.ID})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/roles", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", g.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AssignRoleToGroup(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR3_ListProjectInvitations(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj := &models.Project{Name: "contract-pr3-invite-list-proj"}
	require.NoError(t, db.Create(proj).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/invitations", nil),
		"id", fmt.Sprintf("%d", proj.ID),
	))
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_CreateProjectInvitation(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj := &models.Project{Name: "contract-pr3-invite-create-proj"}
	require.NoError(t, db.Create(proj).Error)
	role := &models.Role{Name: "contract-pr3-invite-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{"email": "invitee@example.test", "role": role.Name})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", proj.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateInvitation(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR3_ResendProjectInvitation(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	// Out-of-band delivery (nil deliverer) plus a configured base URL, so
	// ResendInvitationLink doesn't hit ErrSetupBaseURLRequired -- otherwise the
	// handler maps that to 400, which isn't the happy path this test wants.
	cs.SetCredentialDelivery(nil, "https://contract-pr3.example.test")
	h := NewCatalogHandler(cs)
	proj := &models.Project{Name: "contract-pr3-invite-resend-proj"}
	require.NoError(t, db.Create(proj).Error)
	inv := &models.ProjectInvitation{ProjectID: proj.ID, Email: "resend@example.test", Role: "viewer", State: "pending"}
	require.NoError(t, db.Create(inv).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/invitations/1/resend", nil),
		"id", fmt.Sprintf("%d", proj.ID), "invitationId", fmt.Sprintf("%d", inv.ID),
	))
	w := httptest.NewRecorder()
	h.ResendInvitation(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_RevokeProjectInvitation(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj := &models.Project{Name: "contract-pr3-invite-revoke-proj"}
	require.NoError(t, db.Create(proj).Error)
	inv := &models.ProjectInvitation{ProjectID: proj.ID, Email: "revoke@example.test", Role: "viewer", State: "pending"}
	require.NoError(t, db.Create(inv).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodDelete, "/api/v1/projects/1/invitations/1", nil),
		"id", fmt.Sprintf("%d", proj.ID), "invitationId", fmt.Sprintf("%d", inv.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeInvitation(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_ListProjectEnvironments(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj := &models.Project{Name: "contract-pr3-env-proj"}
	require.NoError(t, db.Create(proj).Error)
	require.NoError(t, db.Create(&models.Environment{ProjectID: proj.ID, Name: "production"}).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/environments", nil),
		"id", fmt.Sprintf("%d", proj.ID),
	))
	w := httptest.NewRecorder()
	h.ListProjectEnvironments(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_ListUsers(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_GetUserRolesForUser(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewUsersRolesHandler(cs)
	u := &models.User{Username: "contract-pr3-roles-user", Email: "contract-pr3-roles-user@example.test", DisplayName: "U"}
	require.NoError(t, db.Create(u).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/users/1/roles", nil),
		"id", fmt.Sprintf("%d", u.ID),
	))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_ListRoles(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	require.NoError(t, db.Create(&models.Role{Name: "contract-pr3-list-role", Description: "d"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil))
	w := httptest.NewRecorder()
	h.ListRoles(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_GetRolePermissions(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "contract-pr3-role-perms", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/roles/1/permissions", nil),
		"id", fmt.Sprintf("%d", role.ID),
	))
	w := httptest.NewRecorder()
	h.GetRolePermissions(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_AssignUserRole(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	u := &models.User{Username: "contract-pr3-assign-user", Email: "contract-pr3-assign-user@example.test", DisplayName: "U"}
	require.NoError(t, db.Create(u).Error)
	role := &models.Role{Name: "contract-pr3-assign-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{"user_id": u.ID, "role_id": role.ID})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.AssignRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR3_ListRBACAuditLogs(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuditHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/rbac-logs", nil))
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR3_GetPermissionMatrix(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/rbac/permission-matrix", nil))
	w := httptest.NewRecorder()
	h.GetPermissionMatrix(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
