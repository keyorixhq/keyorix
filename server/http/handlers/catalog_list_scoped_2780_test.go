// catalog_list_scoped_2780_test.go — #2780: GET /api/v1/projects and
// GET /api/v1/environments return what the caller can read, not a 403.
//
// The persona these tests build is the one WEB-SWEEP-1 walked the UI as, and the
// ordinary shape for a developer handed access to one service: `system_viewer` at
// global scope (so `system.read` only) plus `project_viewer` on ONE project. That
// account could already read the project's secrets via GET /api/v1/secrets and the
// project itself via GET /api/v1/projects/{id}, but the listing 403'd — so the
// project switcher, the /projects page, and the New Secret dialog's required
// Project/Environment selects all came up empty, and because the switcher fires
// from the layout, that 403 happened on every route in the app.
//
// Two of these tests are the change (red before, green after). The rest are the
// invariants that must hold BEFORE and AFTER, which is the brief's rule: a fix may
// only make listing consistent with what is already readable, never generous.
//   - a user with no grant anywhere sees no project / no environment
//   - a user granted project A never sees project B
//   - a global reader's list is byte-for-byte unchanged
//   - an ENVIRONMENT-only grant does not reveal its parent project, because that
//     caller cannot GET the project by id either
//   - ?include_deleted=true still requires a global grant
package handlers

import (
	"context"
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
)

// p2780World is the fixture: two projects, each with two environments, and the
// roles/permissions needed to build each persona.
type p2780World struct {
	h        *CatalogHandler
	db       *gorm.DB
	projectA uint
	projectB uint
	envA1    uint
	envB1    uint
}

func new2780World(t *testing.T) *p2780World {
	t.Helper()
	db := openTestDB(t)
	// ListProjectsWithCounts LEFT JOINs secret_nodes for its per-project secret
	// count, so the table has to exist even when no secret is seeded.
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	// openTestDB grants UserID 1 a GLOBAL system_admin role (BypassesPermissionChecks)
	// without creating the users row, so the first user any test creates lands on ID 1
	// and silently inherits install-wide admin — which would make every "scoped reader
	// sees only their project" assertion below pass for the wrong reason, or fail
	// confusingly. Occupy ID 1 with the admin it was meant for.
	require.NoError(t, db.Create(&models.User{
		Username: "p2780-install-admin", Email: "p2780-install-admin@example.com", PasswordHash: "x",
	}).Error)
	h := NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	a := &models.Project{Name: "payments-api"}
	b := &models.Project{Name: "billing"}
	require.NoError(t, db.Create(a).Error)
	require.NoError(t, db.Create(b).Error)
	envA1 := &models.Environment{ProjectID: a.ID, Name: "prod"}
	envA2 := &models.Environment{ProjectID: a.ID, Name: "staging"}
	envB1 := &models.Environment{ProjectID: b.ID, Name: "prod"}
	for _, e := range []*models.Environment{envA1, envA2, envB1} {
		require.NoError(t, db.Create(e).Error)
	}
	return &p2780World{h: h, db: db, projectA: a.ID, projectB: b.ID, envA1: envA1.ID, envB1: envB1.ID}
}

// grantScoped creates a user holding secrets.read at the given scope and returns
// their ID. projectID/environmentID 0 means the global scope.
func (w *p2780World) grantScoped(t *testing.T, username string, projectID, environmentID uint) uint {
	t.Helper()
	u := &models.User{Username: username, Email: username + "@example.com", PasswordHash: "x"}
	require.NoError(t, w.db.Create(u).Error)
	role := mustCreateRole(t, w.db, "p2780-reader-"+username)
	// permissions.name is unique, so reuse the row when a second persona in the same
	// test needs the same permission (mustCreatePermission would fail on the insert).
	perm := &models.Permission{}
	if err := w.db.Where("name = ?", "secrets.read").First(perm).Error; err != nil {
		perm = &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		require.NoError(t, w.db.Create(perm).Error)
	}
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{
		UserID: u.ID, RoleID: role.ID, ProjectID: projectID, EnvironmentID: environmentID,
	}).Error)
	return u.ID
}

// req2780Ctx is a bare context for the direct AuthorizePrincipal precondition check
// below (no request, so no actor-type tagging to carry).
func req2780Ctx() context.Context { return context.Background() }

// newUserNoGrants creates a user with no role at all.
func (w *p2780World) newUserNoGrants(t *testing.T, username string) uint {
	t.Helper()
	u := &models.User{Username: username, Email: username + "@example.com", PasswordHash: "x"}
	require.NoError(t, w.db.Create(u).Error)
	return u.ID
}

// listProjectsAs drives GET /api/v1/projects as userID and returns the status plus
// the project IDs in the response.
func (w *p2780World) listProjectsAs(t *testing.T, userID uint, query string) (int, []uint) {
	t.Helper()
	req := withUserCtxID(httptest.NewRequest(http.MethodGet, "/api/v1/projects"+query, nil), userID, fmt.Sprintf("u%d", userID))
	rec := httptest.NewRecorder()
	w.h.ListProjects(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var env struct {
		Data struct {
			Projects []struct {
				ID uint `json:"id"`
			} `json:"projects"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body: %s", rec.Body.String())
	ids := make([]uint, 0, len(env.Data.Projects))
	for _, p := range env.Data.Projects {
		ids = append(ids, p.ID)
	}
	return rec.Code, ids
}

// listEnvironmentsAs drives GET /api/v1/environments as userID.
func (w *p2780World) listEnvironmentsAs(t *testing.T, userID uint) (int, []uint) {
	t.Helper()
	req := withUserCtxID(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil), userID, fmt.Sprintf("u%d", userID))
	rec := httptest.NewRecorder()
	w.h.ListEnvironments(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var env struct {
		Data struct {
			Environments []struct {
				ID        uint `json:"id"`
				ProjectID uint `json:"project_id"`
			} `json:"environments"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), "body: %s", rec.Body.String())
	ids := make([]uint, 0, len(env.Data.Environments))
	for _, e := range env.Data.Environments {
		ids = append(ids, e.ProjectID)
	}
	return rec.Code, ids
}

// TestListProjects2780_ProjectScopedReaderSeesTheirProject is the regression.
// Red before the fix: the route's RequirePermission(secrets.read) middleware
// answered 403 for this persona, and the handler never ran.
func TestListProjects2780_ProjectScopedReaderSeesTheirProject(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-viewer", w.projectA, 0)

	code, ids := w.listProjectsAs(t, uid, "")

	require.Equal(t, http.StatusOK, code,
		"a project-scoped reader must not be 403'd out of the project listing (#2780) — "+
			"they can already read this project via GET /api/v1/projects/{id}")
	assert.Equal(t, []uint{w.projectA}, ids,
		"exactly the one project they hold a grant in — not zero, and not the other project")
}

// TestListEnvironments2780_ProjectScopedReaderSeesTheirEnvironments covers the
// sibling endpoint. It is not cosmetic: the web New Secret dialog's required
// Environment select reads THIS endpoint, so without it that dialog stays
// unsatisfiable for exactly this persona.
func TestListEnvironments2780_ProjectScopedReaderSeesTheirEnvironments(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-envviewer", w.projectA, 0)

	code, projectIDs := w.listEnvironmentsAs(t, uid)

	require.Equal(t, http.StatusOK, code, "a project-scoped reader must not be 403'd out of the environment listing")
	require.Len(t, projectIDs, 2, "both of project A's environments")
	for _, pid := range projectIDs {
		assert.Equal(t, w.projectA, pid, "no environment from a project this caller cannot read")
	}
}

// TestListProjects2780_NoGrantsSeesNothing — must hold before and after. A caller
// with no grant anywhere sees no project. 200-with-empty rather than 403 is the
// deliberate part: the 403 is what made the dashboard assert "you have nothing".
func TestListProjects2780_NoGrantsSeesNothing(t *testing.T) {
	w := new2780World(t)
	// Someone else holds project A, so the world is not empty and the empty result
	// below is meaningful rather than vacuous.
	w.grantScoped(t, "p2780-other", w.projectA, 0)
	uid := w.newUserNoGrants(t, "p2780-nobody")

	code, ids := w.listProjectsAs(t, uid, "")

	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, ids, "a caller with no project grant must see no project")

	ecode, eids := w.listEnvironmentsAs(t, uid)
	require.Equal(t, http.StatusOK, ecode)
	assert.Empty(t, eids, "...and no environment")
}

// TestListProjects2780_GrantOnANeverRevealsB — must hold before and after. This is
// the brief's hard rule stated as a test: the fix may only make listing consistent
// with what is already readable.
func TestListProjects2780_GrantOnANeverRevealsB(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-a-only", w.projectA, 0)

	_, ids := w.listProjectsAs(t, uid, "")
	assert.NotContains(t, ids, w.projectB, "a grant on project A must never reveal project B")

	_, projectIDs := w.listEnvironmentsAs(t, uid)
	assert.NotContains(t, projectIDs, w.projectB, "...nor project B's environments")
}

// TestListProjects2780_GlobalReaderListUnchanged — the no-loss half. A global
// secrets.read holder is authorized at Scope{}, so VisibleProjects reports All and
// the list is not filtered at all.
func TestListProjects2780_GlobalReaderListUnchanged(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-global", 0, 0)

	code, ids := w.listProjectsAs(t, uid, "")
	require.Equal(t, http.StatusOK, code)
	assert.ElementsMatch(t, []uint{w.projectA, w.projectB}, ids,
		"a global reader must still see every project — the fix narrows for scoped callers, it must not narrow for them")

	ecode, projectIDs := w.listEnvironmentsAs(t, uid)
	require.Equal(t, http.StatusOK, ecode)
	assert.Len(t, projectIDs, 3, "all three environments across both projects")
}

// TestListProjects2780_EnvironmentOnlyGrantDoesNotRevealTheProject is the sharp
// edge, and the reason core.VisibleProjects re-authorizes at the PROJECT scope
// instead of trusting GetReadableScopes' raw scope list.
//
// GetUserRoleIDsAt matches `environment_id = 0 OR environment_id = <asked>`, so a
// grant at (project A, environment prod) does NOT authorize (project A,
// environment 0) — which is the scope GET /api/v1/projects/{id} checks. Such a
// caller genuinely cannot read project A by id today, so listing it for them would
// be NEW disclosure, not a consistency fix.
func TestListProjects2780_EnvironmentOnlyGrantDoesNotRevealTheProject(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-envonly", w.projectA, w.envA1)

	// Precondition: this caller really is refused the per-project read, so the
	// assertion below is about parity with GET /projects/{id} rather than an
	// arbitrary choice.
	cs := core.NewKeyorixCore(store.NewLocalStorage(w.db))
	allowed, err := cs.AuthorizePrincipal(req2780Ctx(), core.ActorTypeUser, uid, "secrets.read", core.Scope{ProjectID: w.projectA})
	require.NoError(t, err)
	require.False(t, allowed, "fixture precondition: an environment-only grant does not authorize the project scope")

	code, ids := w.listProjectsAs(t, uid, "")
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, ids,
		"an environment-only grant must not surface its parent project — that caller cannot GET it by id either")
}

// TestListProjects2780_IncludeDeletedStillRequiresGlobal keeps the restore view
// admin-only. Project-scoped role grants are deliberately left in place across a
// soft-delete (to support RestoreProject) while GetProject 404s on a deleted
// project, so a project-scoped reader cannot read a soft-deleted project through
// ANY path today — filtering by readable scope alone would newly disclose it.
func TestListProjects2780_IncludeDeletedStillRequiresGlobal(t *testing.T) {
	w := new2780World(t)
	scoped := w.grantScoped(t, "p2780-scoped-restore", w.projectA, 0)
	global := w.grantScoped(t, "p2780-global-restore", 0, 0)

	code, _ := w.listProjectsAs(t, scoped, "?include_deleted=true")
	assert.Equal(t, http.StatusForbidden, code,
		"the soft-deleted view stays global-only: a scoped reader cannot read a deleted project by id, "+
			"so listing one for them would be new disclosure")

	gcode, _ := w.listProjectsAs(t, global, "?include_deleted=true")
	assert.Equal(t, http.StatusOK, gcode, "a global reader still gets the restore view")
}

// TestListProjects2780_UnauthenticatedIsRejected — the route no longer carries
// RequirePermission middleware, so the handler itself must refuse a request with
// no user context rather than treating it as an anonymous global reader.
func TestListProjects2780_UnauthenticatedIsRejected(t *testing.T) {
	w := new2780World(t)

	rec := httptest.NewRecorder()
	w.h.ListProjects(rec, httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "no user context must not fall through to an unfiltered list")

	erec := httptest.NewRecorder()
	w.h.ListEnvironments(erec, httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil))
	assert.Equal(t, http.StatusUnauthorized, erec.Code)
}
