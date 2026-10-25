package http

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GROUP-ROLE-SCOPE-1 Phase 2 (#3546): a role's assignable scope is set and
// changed through the role API and decides where its grants may be written.
// Every case asserts the effect (rows read back), not only the status.

func (w *roleScopeHTTPWorld) put(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, w.server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+roleScopeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, sb.String()
}

func (w *roleScopeHTTPWorld) storedScope(t *testing.T, roleID uint) string {
	t.Helper()
	var r models.Role
	require.NoError(t, w.db.First(&r, roleID).Error)
	return r.AssignableScope
}

// createRoleHTTP creates a custom role through POST /api/v1/roles and returns
// its ID and the assignable_scope the response reported.
func (w *roleScopeHTTPWorld) createRoleHTTP(t *testing.T, body string) (uint, string) {
	t.Helper()
	require.NoError(t, w.db.FirstOrCreate(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	status, resp := w.post(t, "/api/v1/roles", body)
	require.Equal(t, http.StatusCreated, status, resp)
	var out struct {
		Data struct {
			Role struct {
				ID              uint   `json:"id"`
				AssignableScope string `json:"assignable_scope"`
			} `json:"role"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp), &out), resp)
	require.NotZero(t, out.Data.Role.ID)
	return out.Data.Role.ID, out.Data.Role.AssignableScope
}

func TestCreateRoleHTTP_NewRoleIsProjectScopedByDefault(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	id, reported := w.createRoleHTTP(t, `{"name":"deployers","description":"ci","permissions":["secrets.read"]}`)
	require.Equal(t, models.RoleAssignableProject, reported, "the response reports the scope")
	require.Equal(t, models.RoleAssignableProject, w.storedScope(t, id))

	status, body := w.post(t, "/api/v1/groups/7/roles", fmt.Sprintf(`{"role_id":%d}`, id))
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "role deployers is project-scoped")
	require.Empty(t, w.groupGrants(t, 7))

	status, body = w.post(t, "/api/v1/groups/7/roles", fmt.Sprintf(`{"role_id":%d,"project_id":2}`, id))
	require.Equal(t, http.StatusCreated, status, body)
	require.Equal(t, []models.GroupRole{{GroupID: 7, RoleID: id, ProjectID: 2}}, w.groupGrants(t, 7))
}

func TestCreateRoleHTTP_ExplicitScopeAndValidation(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	id, reported := w.createRoleHTTP(t, `{"name":"ops-all","description":"ops","permissions":["secrets.read"],"assignable_scope":"any"}`)
	require.Equal(t, models.RoleAssignableAny, reported)
	require.Equal(t, models.RoleAssignableAny, w.storedScope(t, id))
	status, body := w.post(t, "/api/v1/groups/7/roles", fmt.Sprintf(`{"role_id":%d}`, id))
	require.Equal(t, http.StatusCreated, status, body)

	status, body = w.post(t, "/api/v1/roles", `{"name":"bad-scope","description":"x","permissions":["secrets.read"],"assignable_scope":"everywhere"}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	var n int64
	require.NoError(t, w.db.Model(&models.Role{}).Where("name = ?", "bad-scope").Count(&n).Error)
	require.Zero(t, n, "an invalid scope creates no role")
}

func TestUpdateRoleHTTP_WideningAllowsAGlobalGrant(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	id, _ := w.createRoleHTTP(t, `{"name":"deployers","description":"ci","permissions":["secrets.read"]}`)

	status, body := w.put(t, fmt.Sprintf("/api/v1/roles/%d", id), `{"assignable_scope":"bogus"}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Equal(t, models.RoleAssignableProject, w.storedScope(t, id), "a refused update changes nothing")

	status, body = w.put(t, fmt.Sprintf("/api/v1/roles/%d", id), `{"assignable_scope":"any"}`)
	require.Equal(t, http.StatusOK, status, body)
	require.Contains(t, body, `"assignable_scope":"any"`)
	require.Equal(t, models.RoleAssignableAny, w.storedScope(t, id))

	status, body = w.post(t, "/api/v1/groups/7/roles", fmt.Sprintf(`{"role_id":%d}`, id))
	require.Equal(t, http.StatusCreated, status, body)

	// A description-only update keeps the stored scope.
	status, body = w.put(t, fmt.Sprintf("/api/v1/roles/%d", id), `{"description":"still any"}`)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, models.RoleAssignableAny, w.storedScope(t, id))
}

func TestUpdateRoleHTTP_BuiltinScopeIsImmutable(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	status, body := w.put(t, "/api/v1/roles/10", `{"assignable_scope":"any"}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Equal(t, models.RoleAssignableProject, w.storedScope(t, 10))
}

// TestAssignRoleHTTP_InstallWideRoleAtAProjectIsRefused: Phase 2's other
// direction. A system role is install-wide; offered on one project it is
// refused, user and group alike.
func TestAssignRoleHTTP_InstallWideRoleAtAProjectIsRefused(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	status, body := w.post(t, "/api/v1/groups/7/roles", `{"role_id":11,"project_id":2}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "role system_admin is install-wide")
	require.Empty(t, w.groupGrants(t, 7))

	status, body = w.post(t, "/api/v1/user-roles", `{"user_id":3,"role_id":11,"project_id":2}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Empty(t, w.userGrants(t, 3))
}

// TestAddProjectMemberHTTP_InstallWideRoleIs400 is #3554 review follow-up 5 on
// a real route: the refusal used to fall through to the handler's 500.
func TestAddProjectMemberHTTP_InstallWideRoleIs400(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	status, body := w.post(t, "/api/v1/projects/2/members", `{"user_id":3,"role":"system_admin"}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "install-wide")
	require.Empty(t, w.userGrants(t, 3))
}

// TestCreateUserHTTP_InstallWideRoleInAProjectAssignmentIsRefused is
// REVIEW-3585-DEEP-1 F2: POST /users wrote {system_admin @ project 2} because
// CreateUserWithAssignments skipped the scope check on its project assignments.
// Refused now, and neither the user nor any grant is written.
func TestCreateUserHTTP_InstallWideRoleInAProjectAssignmentIsRefused(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	// The default system role, so the request reaches its project assignments.
	require.NoError(t, w.db.Create(&models.Role{ID: 12, Name: "system_viewer", NameFolded: "system_viewer"}).Error)
	users := func() int64 {
		var n int64
		require.NoError(t, w.db.Model(&models.User{}).Count(&n).Error)
		return n
	}
	before := users()

	status, body := w.post(t, "/api/v1/users",
		`{"username":"frank","email":"frank@test.com","display_name":"Frank","password":"Correct-Horse-Battery-9","project_assignments":[{"project_id":2,"role":"system_admin"}]}`)
	require.Equal(t, http.StatusBadRequest, status, body)
	require.Contains(t, body, "role system_admin is install-wide")
	require.Equal(t, before, users(), "no user may be created behind a refused assignment")
	var grants int64
	require.NoError(t, w.db.Model(&models.UserRole{}).Where("role_id = ?", 11).Count(&grants).Error)
	require.Zero(t, grants, "no system_admin grant may be written")

	// Positive control: a project role in the same assignment is created.
	status, body = w.post(t, "/api/v1/users",
		`{"username":"frank","email":"frank@test.com","display_name":"Frank","password":"Correct-Horse-Battery-9","project_assignments":[{"project_id":2,"role":"project_developer"}]}`)
	require.Equal(t, http.StatusCreated, status, body)
	var frank models.User
	require.NoError(t, w.db.Where("username = ?", "frank").First(&frank).Error)
	require.Equal(t, []models.UserRole{{UserID: frank.ID, RoleID: 10, ProjectID: 2}, {UserID: frank.ID, RoleID: 12}},
		stripUserRoleIDs(w.userGrants(t, frank.ID)))
}

func stripUserRoleIDs(in []models.UserRole) []models.UserRole {
	out := make([]models.UserRole, 0, len(in))
	for _, g := range in {
		out = append(out, models.UserRole{UserID: g.UserID, RoleID: g.RoleID, ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID})
	}
	return out
}

// TestUpdateRoleHTTP_ConcurrentNarrowingIsKept is REVIEW-3585-DEEP-1 F4: admin A
// sends a description-only update while admin B narrows the role any -> project.
// The handler reads the role before core's transaction; B's narrowing commits
// right after that read (the callback below). The handler used to send A's
// stale `any` back, which core took for a widening and wrote: B's narrowing was
// silently undone. Leaving the field out now keeps the stored scope.
func TestUpdateRoleHTTP_ConcurrentNarrowingIsKept(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	id, _ := w.createRoleHTTP(t, `{"name":"ops-all","description":"ops","permissions":["secrets.read"],"assignable_scope":"any"}`)

	armed := true
	require.NoError(t, w.db.Callback().Query().After("gorm:query").Register("test:narrow-after-handler-read", func(tx *gorm.DB) {
		if _, inTx := tx.Statement.ConnPool.(*sql.Tx); inTx || !armed {
			return
		}
		if r, ok := tx.Statement.Dest.(*models.Role); ok && r.ID == id {
			armed = false // admin B's narrowing commits between A's read and A's transaction
			require.NoError(t, w.db.Model(&models.Role{}).Where("id = ?", id).Update("assignable_scope", models.RoleAssignableProject).Error)
		}
	}))

	status, body := w.put(t, fmt.Sprintf("/api/v1/roles/%d", id), `{"description":"renamed by A"}`)
	require.Equal(t, http.StatusOK, status, body)
	require.False(t, armed, "the concurrent narrowing never landed in the handler's read window")
	require.Equal(t, models.RoleAssignableProject, w.storedScope(t, id), "A's description-only update undid B's narrowing")
	var r models.Role
	require.NoError(t, w.db.First(&r, id).Error)
	require.Equal(t, "renamed by A", r.Description)
}
