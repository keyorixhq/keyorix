package handlers

// err_family6_grant_ceiling_test.go — CORE-ERR-FAMILY-6 item 3.
//
// The grant ceiling (requireGranterHoldsRolePermissions and its siblings) refuses with
// core.ErrPermissionDenied. Two handlers answered it 403 by looking for the English
// words "cannot grant this role" in the error text, which breaks the day core rewords
// the refusal. Handlers classify by sentinel; this file holds
//
//   - a static guard: no handler source mentions the phrase,
//   - a runtime family test: every grant route answers a ceiling refusal 403.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const grantCeilingPhrase = "cannot grant this role"

// grantCeilingTextMatches returns the position of every string literal in src that
// contains the grant-ceiling refusal text. A handler has no reason to spell it: it
// classifies with errors.Is(err, core.ErrPermissionDenied).
func grantCeilingTextMatches(t *testing.T, filename string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	require.NoError(t, err)
	var hits []string
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, grantCeilingPhrase) {
			hits = append(hits, fset.Position(lit.Pos()).String())
		}
		return true
	})
	return hits
}

func TestNoHandlerMatchesTheGrantCeilingRefusalText(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(srcpath.PkgDir(), "*.go"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	var bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		bad = append(bad, grantCeilingTextMatches(t, f, nil)...)
	}
	assert.Empty(t, bad, "classify a grant-ceiling refusal with errors.Is(err, core.ErrPermissionDenied), not by its text")
}

// The scan fires on the old shape and spares the sentinel.
func TestGrantCeilingTextScanCalibration(t *testing.T) {
	const old = `package p
func f(err error) bool { return strings.Contains(err.Error(), "cannot grant this role") }`
	const now = `package p
func f(err error) bool { return errors.Is(err, core.ErrPermissionDenied) }`
	assert.Len(t, grantCeilingTextMatches(t, "old", old), 1)
	assert.Empty(t, grantCeilingTextMatches(t, "now", now))
}

// TestEveryGrantRouteMapsTheCeilingRefusalTo403 drives each handler that grants a role (eight routes)
// as an actor who holds roles.assign but not the permissions of the role it grants.
// Core refuses (core.ErrPermissionDenied); every route must answer 403, never 500/400.
func TestEveryGrantRouteMapsTheCeilingRefusalTo403(t *testing.T) {
	fw := newFoldWorld(t)
	ctx := t.Context()
	local := fw.local

	// The foldWorld admin holds a bypass role; replace it with a role that may assign
	// roles but nothing else, so the ceiling (not the route gate) is what refuses.
	require.NoError(t, fw.db.Exec("DELETE FROM user_roles").Error)
	assignerName, err := identity.NewFoldedName("fam6-assigner")
	require.NoError(t, err)
	assigner, err := local.CreateRole(ctx, assignerName, "")
	require.NoError(t, err)
	powerfulName, err := identity.NewFoldedName("fam6-powerful")
	require.NoError(t, err)
	powerful, err := local.CreateRole(ctx, powerfulName, "")
	require.NoError(t, err)
	perm := func(name string) *models.Permission {
		res, act, _ := strings.Cut(name, ".")
		p, perr := local.CreatePermission(ctx, &models.Permission{Name: name, Resource: res, Action: act})
		require.NoError(t, perr)
		return p
	}
	for _, name := range []string{"roles.assign", "users.write", "projects.write", "groups.write"} {
		require.NoError(t, local.AssignPermissionToRole(ctx, assigner.ID, perm(name).ID))
	}
	// The role being granted carries a permission the actor does not hold.
	secretsWrite := perm("secrets.write")
	require.NoError(t, local.AssignPermissionToRole(ctx, powerful.ID, secretsWrite.ID))
	// A new user also receives the system_viewer baseline and an install-wide system
	// role, both of which the actor must be able to grant.
	for _, name := range []string{"system_viewer", "fam6-global"} {
		fn, ferr := identity.NewFoldedName(name)
		require.NoError(t, ferr)
		r, rerr := local.CreateRole(ctx, fn, "")
		require.NoError(t, rerr)
		require.NoError(t, fw.db.Model(&models.Role{}).Where("id = ?", r.ID).Update("assignable_scope", models.RoleAssignableGlobal).Error)
		require.NoError(t, local.AssignPermissionToRole(ctx, r.ID, secretsWrite.ID))
	}
	require.NoError(t, local.AssignRole(ctx, fw.admin.ID, assigner.ID, corestorage.Scope{}))

	proj := &models.Project{Name: "fam6-grant-proj"}
	require.NoError(t, fw.db.Create(proj).Error)
	target, err := local.CreateUser(ctx, &models.User{
		Username: "fam6-target", UsernameFolded: "fam6-target", Email: "fam6-target@example.com", EmailFolded: "fam6-target@example.com",
		IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)
	grp := &models.Group{Name: "fam6-grant-group", NameFolded: "fam6-grant-group"}
	require.NoError(t, fw.db.Create(grp).Error)
	require.NoError(t, fw.db.Create(&models.GroupRole{GroupID: grp.ID, RoleID: powerful.ID, ProjectID: proj.ID}).Error)

	machine, err := fw.cs.CreateMachineIdentity(ctx, proj.ID, "fam6-grant-machine", "service", "", "", fw.admin.ID, 0)
	require.NoError(t, err)

	cat := NewCatalogHandler(fw.cs)
	users, err := NewUserHandler(fw.cs)
	require.NoError(t, err)
	groups, err := NewGroupHandler(fw.cs)
	require.NoError(t, err)
	rbac := NewRBACHandler(fw.cs)
	usersRoles := NewUsersRolesHandler(fw.cs)
	pid, tid, gid, rid := suID(proj.ID), suID(target.ID), suID(grp.ID), suID(powerful.ID)

	routes := []struct {
		name string
		call func() *httptest.ResponseRecorder
	}{
		{"POST /users with a system role", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			users.CreateUser(w, suReq(http.MethodPost, `{"username":"fam6-new","email":"fam6-new@example.com","display_name":"F","password":"Correct-Horse-Battery-9","role":"fam6-global"}`, nil))
			return w
		}},
		{"POST /users with a project assignment", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			users.CreateUser(w, suReq(http.MethodPost, `{"username":"fam6-new2","email":"fam6-new2@example.com","display_name":"F","password":"Correct-Horse-Battery-9","project_assignments":[{"project_id":`+pid+`,"role":"fam6-powerful"}]}`, nil))
			return w
		}},
		{"POST /groups/{id}/members", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			groups.AddGroupMember(w, suReq(http.MethodPost, `{"user_id":`+tid+`,"project_id":`+pid+`}`, map[string]string{"id": gid}))
			return w
		}},
		{"POST /groups/{id}/roles", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			rbac.AssignRoleToGroup(w, suReq(http.MethodPost, `{"role_id":`+rid+`,"project_id":`+pid+`}`, map[string]string{"id": gid}))
			return w
		}},
		{"POST /projects/{id}/members", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.AddProjectMember(w, suReq(http.MethodPost, `{"user_id":`+tid+`,"role":"fam6-powerful"}`, map[string]string{"id": pid}))
			return w
		}},
		{"PUT /projects/{id}/members/{userId}", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.UpdateProjectMember(w, suReq(http.MethodPut, `{"role":"fam6-powerful"}`, map[string]string{"id": pid, "userId": tid}))
			return w
		}},
		{"POST /projects/{id}/machine-identities/{machineId}/roles", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.GrantMachineRole(w, suReq(http.MethodPost, `{"role_id":`+rid+`}`, map[string]string{"id": pid, "machineId": suID(machine.ID)}))
			return w
		}},
		{"PUT /users/{id}/roles", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			usersRoles.UpdateUserRoles(w, suReq(http.MethodPut, `{"role_ids":[`+rid+`],"project_id":`+pid+`}`, map[string]string{"id": tid}))
			return w
		}},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			w := rt.call()
			assert.Equal(t, http.StatusForbidden, w.Code, "a role the actor cannot grant is a refusal: %s", w.Body.String())
		})
	}
}
