// users_memberships_2781_test.go — #2781 at the HTTP boundary.
//
// The existing G84 tests in rbac_real_test.go cover this route's GATE (who may
// read whose memberships) and assert status codes only; they passed throughout the
// bug, because a 200 carrying `{"memberships":[]}` is still a 200. These tests
// assert the BODY, which is where the defect lived: Admin → Users → <user> said
// "Not a member of any project" for every user on an install whose project members
// were added through POST /projects/{id}/members, while that same project's Members
// tab listed them.
//
// Red before the fix (the handler read the ADR-022 journal, which has no row for a
// grant-only member, so `memberships` came back empty); green after.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

// membershipsEnvelope decodes the route's `{data:{memberships:[...]}}` envelope.
type membershipsEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		Memberships []struct {
			ProjectID   uint     `json:"project_id"`
			ProjectName string   `json:"project_name"`
			Role        string   `json:"role"`
			Roles       []string `json:"roles"`
			State       string   `json:"state"`
			ViaGroup    bool     `json:"via_group"`
		} `json:"memberships"`
	} `json:"data"`
}

// get2781Memberships drives GET /api/v1/users/{target}/memberships as the global
// admin seeded by openTestDB (UserID 1) and decodes the body.
func get2781Memberships(t *testing.T, h *UsersRolesHandler, target uint) membershipsEnvelope {
	t.Helper()
	req := withUserCtx(
		withChiParam(httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/users/%d/memberships", target), nil),
			"id", fmt.Sprintf("%d", target)))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var env membershipsEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())
	return env
}

// new2781Fixture opens a DB with the membership models migrated and returns the
// handler plus the raw DB.
func new2781Fixture(t *testing.T) (*UsersRolesHandler, *gorm.DB) {
	t.Helper()
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.ProjectMembership{}, &models.AuditEvent{}))
	return NewUsersRolesHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

// TestUserMemberships2781_GrantOnlyMemberIsReported is the regression itself.
func TestUserMemberships2781_GrantOnlyMemberIsReported(t *testing.T) {
	h, db := new2781Fixture(t)

	project := &models.Project{Name: "payments-api"}
	require.NoError(t, db.Create(project).Error)
	target := &models.User{Username: "p2781-viewer", Email: "p2781-viewer@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(target).Error)
	viewerRole := mustCreateRole(t, db, "project_viewer")
	// Exactly what POST /api/v1/projects/{id}/members persists — a project-scoped
	// role grant, and no ADR-022 journal row.
	require.NoError(t, db.Create(&models.UserRole{
		UserID: target.ID, RoleID: viewerRole.ID, ProjectID: project.ID,
	}).Error)
	var journalRows int64
	require.NoError(t, db.Model(&models.ProjectMembership{}).Count(&journalRows).Error)
	require.Zero(t, journalRows, "precondition: the journal is empty, as on a UI-driven install")

	env := get2781Memberships(t, h, target.ID)

	require.Len(t, env.Data.Memberships, 1,
		"the user holds a project-scoped grant, so this route must report the membership — "+
			"returning [] here is #2781, and it renders as \"Not a member of any project\"")
	got := env.Data.Memberships[0]
	assert.Equal(t, project.ID, got.ProjectID)
	assert.Equal(t, "payments-api", got.ProjectName)
	assert.Equal(t, "project_viewer", got.Role)
	assert.Equal(t, []string{"project_viewer"}, got.Roles)
	assert.Equal(t, "active", got.State)
	assert.False(t, got.ViaGroup)
}

// TestUserMemberships2781_AgreesWithProjectMembersRoute asserts the two screens
// against each other through their real handlers, which is the property #2781 is
// about — not just that one of them is non-empty.
func TestUserMemberships2781_AgreesWithProjectMembersRoute(t *testing.T) {
	h, db := new2781Fixture(t)
	catalog := NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	project := &models.Project{Name: "billing"}
	require.NoError(t, db.Create(project).Error)
	target := &models.User{Username: "p2781-admin", Email: "p2781-admin@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(target).Error)
	adminRole := mustCreateRole(t, db, "project_admin")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: target.ID, RoleID: adminRole.ID, ProjectID: project.ID,
	}).Error)

	// Project -> Members.
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/members", project.ID), nil),
		"id", fmt.Sprintf("%d", project.ID)))
	w := httptest.NewRecorder()
	catalog.ListProjectMembers(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var membersEnv struct {
		Data struct {
			Members []struct {
				UserID   uint   `json:"user_id"`
				RoleName string `json:"role_name"`
			} `json:"members"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &membersEnv), "body: %s", w.Body.String())
	require.Len(t, membersEnv.Data.Members, 1, "Project -> Members lists the user")
	require.Equal(t, target.ID, membersEnv.Data.Members[0].UserID)

	// Admin -> Users -> <user>.
	env := get2781Memberships(t, h, target.ID)
	require.Len(t, env.Data.Memberships, 1,
		"Project -> Members lists this user, so Admin -> Users must not say they are in no project")
	assert.Equal(t, project.ID, env.Data.Memberships[0].ProjectID)
	assert.Equal(t, membersEnv.Data.Members[0].RoleName, env.Data.Memberships[0].Role,
		"the two screens must agree on the role, not just on the membership")
}

// TestUserMemberships2781_UserWithNoGrantSeesNothing is the invariant that must hold
// before AND after: the fix may only make the view consistent with the grants, never
// generous. The world is deliberately non-empty, so an empty result is meaningful
// rather than vacuous.
func TestUserMemberships2781_UserWithNoGrantSeesNothing(t *testing.T) {
	h, db := new2781Fixture(t)

	project := &models.Project{Name: "payments-api"}
	require.NoError(t, db.Create(project).Error)
	member := &models.User{Username: "p2781-member", Email: "p2781-member@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(member).Error)
	outsider := &models.User{Username: "p2781-outsider", Email: "p2781-outsider@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(outsider).Error)
	viewerRole := mustCreateRole(t, db, "project_viewer")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: member.ID, RoleID: viewerRole.ID, ProjectID: project.ID,
	}).Error)

	// The member is reported (so the fixture really does produce rows)...
	require.Len(t, get2781Memberships(t, h, member.ID).Data.Memberships, 1)
	// ...and the outsider is not.
	assert.Empty(t, get2781Memberships(t, h, outsider.ID).Data.Memberships,
		"a user with no project-scoped grant must appear in no project")
}

// TestUserMemberships2781_GlobalGrantIsNotMembership pins the half of the definition
// that keeps the fix from being a disclosure: holding the install-wide baseline must
// not make a user read as a member of every project. Must hold before and after.
func TestUserMemberships2781_GlobalGrantIsNotMembership(t *testing.T) {
	h, db := new2781Fixture(t)

	for _, name := range []string{"payments-api", "billing"} {
		require.NoError(t, db.Create(&models.Project{Name: name}).Error)
	}
	target := &models.User{Username: "p2781-baseline", Email: "p2781-baseline@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(target).Error)
	baseline := mustCreateRole(t, db, "system_viewer")
	// project_id 0 — the global-scope sentinel, which every SSO/JIT user holds.
	require.NoError(t, db.Create(&models.UserRole{UserID: target.ID, RoleID: baseline.ID, ProjectID: 0}).Error)

	assert.Empty(t, get2781Memberships(t, h, target.ID).Data.Memberships,
		"a global (project_id = 0) grant is not membership of any project")
}

// TestUserMemberships2781_JournalStateSurfacedOnGrantMember confirms the ADR-022
// journal keeps its job: it supplies the lifecycle state for a membership the grant
// already established, rather than deciding whether the membership exists.
func TestUserMemberships2781_JournalStateSurfacedOnGrantMember(t *testing.T) {
	h, db := new2781Fixture(t)

	project := &models.Project{Name: "payments-api"}
	require.NoError(t, db.Create(project).Error)
	target := &models.User{Username: "p2781-provisioned", Email: "p2781-provisioned@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(target).Error)
	viewerRole := mustCreateRole(t, db, "project_viewer")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: target.ID, RoleID: viewerRole.ID, ProjectID: project.ID,
	}).Error)
	require.NoError(t, db.Create(&models.ProjectMembership{
		ProjectID: project.ID, UserID: target.ID, Role: "project_viewer", State: "provisioned",
	}).Error)

	env := get2781Memberships(t, h, target.ID)
	require.Len(t, env.Data.Memberships, 1)
	assert.Equal(t, "provisioned", env.Data.Memberships[0].State,
		"the journal's state must reach the UI as-is")
}

// TestContract2781_GetUserMembershipsForUser validates the response against the
// response schema this change added to openapi.yaml, so the shape the web types are
// generated from is derived from the handler rather than asserted alongside it
// (ADR-074). It is this operation's entry in contracttest's exercisingTests.
func TestContract2781_GetUserMembershipsForUser(t *testing.T) {
	h, db := new2781Fixture(t)

	project := &models.Project{Name: "contract-2781-proj"}
	require.NoError(t, db.Create(project).Error)
	target := &models.User{Username: "contract-2781-user", Email: "contract-2781-user@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(target).Error)
	role := mustCreateRole(t, db, "contract-2781-project-viewer")
	require.NoError(t, db.Create(&models.UserRole{
		UserID: target.ID, RoleID: role.ID, ProjectID: project.ID,
	}).Error)

	req := withUserCtx(
		withChiParam(httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/users/%d/memberships", target.ID), nil),
			"id", fmt.Sprintf("%d", target.ID)))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
	// A schema check on an empty array would pass vacuously; assert there is a row
	// for the schema to have validated.
	var env membershipsEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Len(t, env.Data.Memberships, 1, "the contract check must run against a non-empty memberships array")
}
