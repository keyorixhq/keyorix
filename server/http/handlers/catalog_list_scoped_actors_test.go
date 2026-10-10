// catalog_list_scoped_actors_test.go — follow-up item 4's HTTP half: the ACTORS the
// project/environment listings must handle besides an ordinary human user.
//
// #2858's handler tests all use a plain user. Three other principal kinds reach these
// routes in production and each takes a different path through
// core.VisibleProjects:
//
//   - a MACHINE identity (ADR-030): grants resolve via GetMachineRoleScopes, not
//     GetUserRoleScopes (G33), and a machine never gets the admin-role bypass;
//   - a PROJECT-RESTRICTED personal access token (ADR-042): the restriction narrows
//     the token BELOW what its owner can reach, so a global-reader owner's token
//     must see one project, not all of them;
//   - a user whose only grant sits on a SOFT-DELETED project.
//
// The PAT case is the one most worth having: the restriction lives on the request
// CONTEXT, so a listing that authorized off the owner's identity instead of the
// request's would quietly hand a narrowed token the owner's full view. That is the
// confused-deputy shape, and an empty list is not what it would look like — it would
// look like a working feature.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// withScopedMachineCtx injects a machine-actor request context for a specific machine
// id. Both the ActorType FIELD and the core CONTEXT tag are set:
// UserContext.ActorKind()/PrincipalID() branch on the field, while
// core.GetReadableScopes reads the context tag (actorTypeFromContext) and defaults to
// ActorTypeUser. Setting only one resolves the machine as a user with principal id 0 —
// zero scopes, an empty list, and no error, so it reads as a code bug rather than a
// fixture bug.
//
// Distinct from this package's existing withMachineCtx(r), which hard-codes machine 42
// and sets only the field. That is sufficient for ListSecrets' machine branch, which
// authorizes against an explicit project_id and never calls GetReadableScopes — but it
// is not sufficient here, which is exactly why this helper exists rather than reusing it.
func withScopedMachineCtx(r *http.Request, machineID uint) *http.Request {
	uc := &middleware.UserContext{
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}
	ctx := context.WithValue(r.Context(), middleware.GetUserContextKey(), uc)
	ctx = core.WithActorType(ctx, core.ActorTypeMachine)
	return r.WithContext(ctx)
}

// withPATRestrictedCtx injects a user context whose request carries an ADR-042 PAT
// restriction narrowing it to one project.
func withPATRestrictedCtx(r *http.Request, userID, projectID uint) *http.Request {
	uc := &middleware.UserContext{UserID: userID, Username: "p2780-pat", ActorType: core.ActorTypeUser}
	ctx := context.WithValue(r.Context(), middleware.GetUserContextKey(), uc)
	ctx = core.WithPATRestriction(ctx, &core.PATRestriction{ProjectID: projectID})
	return r.WithContext(ctx)
}

// grantMachineScoped seeds an active machine identity with secrets.read at the given
// project scope (0 = global).
func (w *p2780World) grantMachineScoped(t *testing.T, machineID, projectID uint) {
	t.Helper()
	require.NoError(t, w.db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, w.db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: w.projectA, Name: "p2780-ci", State: core.MachineActive,
	}).Error)
	role := mustCreateRole(t, w.db, "p2780-machine-reader")
	perm := &models.Permission{}
	if err := w.db.Where("name = ?", "secrets.read").First(perm).Error; err != nil {
		perm = &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
		require.NoError(t, w.db.Create(perm).Error)
	}
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, w.db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machineID, RoleID: role.ID, ProjectID: projectID,
	}).Error)
}

func p2780DecodeProjectIDs(t *testing.T, body []byte) []uint {
	t.Helper()
	var env struct {
		Data struct {
			Projects []struct {
				ID uint `json:"id"`
			} `json:"projects"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
	ids := make([]uint, 0, len(env.Data.Projects))
	for _, p := range env.Data.Projects {
		ids = append(ids, p.ID)
	}
	return ids
}

// TestListProjects2780_MachineSeesOnlyItsScopedProject covers the machine path.
func TestListProjects2780_MachineSeesOnlyItsScopedProject(t *testing.T) {
	w := new2780World(t)
	w.grantMachineScoped(t, 600, w.projectA)

	req := withScopedMachineCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil), 600)
	rec := httptest.NewRecorder()
	w.h.ListProjects(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	ids := p2780DecodeProjectIDs(t, rec.Body.Bytes())
	assert.Equal(t, []uint{w.projectA}, ids,
		"a machine's grants resolve through GetMachineRoleScopes (G33) — a different branch of "+
			"VisibleProjects than the user path, so it needs its own assertion")
	assert.NotContains(t, ids, w.projectB)
}

// TestListEnvironments2780_MachineSeesOnlyItsScopedEnvironments covers the sibling
// endpoint for the same actor, since it resolves visibility independently.
func TestListEnvironments2780_MachineSeesOnlyItsScopedEnvironments(t *testing.T) {
	w := new2780World(t)
	w.grantMachineScoped(t, 601, w.projectA)

	req := withScopedMachineCtx(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil), 601)
	rec := httptest.NewRecorder()
	w.h.ListEnvironments(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var env struct {
		Data struct {
			Environments []struct {
				ProjectID uint `json:"project_id"`
			} `json:"environments"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	require.NotEmpty(t, env.Data.Environments, "its own project's environments must be listed")
	for _, e := range env.Data.Environments {
		assert.Equal(t, w.projectA, e.ProjectID, "no environment from a project this machine cannot read")
	}
}

// TestListProjects2780_MachineWithNoGrantSeesNothing — the invariant for this actor.
func TestListProjects2780_MachineWithNoGrantSeesNothing(t *testing.T) {
	w := new2780World(t)
	// Someone else holds project A, so the world is not empty.
	w.grantScoped(t, "p2780-other-user", w.projectA, 0)
	require.NoError(t, w.db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, w.db.Create(&models.MachineIdentity{
		ID: 602, ProjectID: w.projectA, Name: "p2780-ci-ungranted", State: core.MachineActive,
	}).Error)

	req := withScopedMachineCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil), 602)
	rec := httptest.NewRecorder()
	w.h.ListProjects(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, p2780DecodeProjectIDs(t, rec.Body.Bytes()),
		"an ungranted machine must see no project — an empty list, not a denial")
}

// TestListProjects2780_ProjectRestrictedTokenSeesOnlyThatProject is the PAT case
// (ADR-042). The owner is a GLOBAL reader, so without the restriction being honoured
// the token would see every project — which is why the positive control below
// asserts exactly that about the unrestricted owner.
func TestListProjects2780_ProjectRestrictedTokenSeesOnlyThatProject(t *testing.T) {
	w := new2780World(t)
	ownerID := w.grantScoped(t, "p2780-pat-owner", 0, 0) // global secrets.read

	// Control: the owner, unrestricted, sees BOTH projects. Without this the
	// assertion below could pass against a listing that is broken for everyone.
	ownerReq := withUserCtxID(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil), ownerID, "p2780-pat-owner")
	ownerRec := httptest.NewRecorder()
	w.h.ListProjects(ownerRec, ownerReq)
	require.Equal(t, http.StatusOK, ownerRec.Code)
	require.ElementsMatch(t, []uint{w.projectA, w.projectB}, p2780DecodeProjectIDs(t, ownerRec.Body.Bytes()),
		"fixture control: the owner is a global reader and sees every project")

	// The same owner, through a token restricted to project A.
	req := withPATRestrictedCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil), ownerID, w.projectA)
	rec := httptest.NewRecorder()
	w.h.ListProjects(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, []uint{w.projectA}, p2780DecodeProjectIDs(t, rec.Body.Bytes()),
		"an ADR-042 project-restricted token must see ONLY its project, even though its owner is a "+
			"global reader — the restriction lives on the request context, so a listing that authorized "+
			"off the owner's identity would hand the narrowed token the owner's full view")
	assert.NotContains(t, p2780DecodeProjectIDs(t, rec.Body.Bytes()), w.projectB)
}

// TestListProjects2780_SoftDeletedProjectIsNotListedForItsGrantHolder: a
// project-scoped grant survives a soft-delete (RestoreProject reinstates it), but
// GetProject 404s on a deleted project, so its holder cannot read it through any path
// and must not see it listed. The default listing already excludes soft-deleted
// projects; this pins that it stays excluded for the one caller who still holds a
// live grant on it, which is the case a naive readable-scope filter would surface.
func TestListProjects2780_SoftDeletedProjectIsNotListedForItsGrantHolder(t *testing.T) {
	w := new2780World(t)
	uid := w.grantScoped(t, "p2780-deleted-holder", w.projectB, 0)

	// Control: listed while live.
	code, ids := w.listProjectsAs(t, uid, "")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, []uint{w.projectB}, ids, "fixture control: listed while the project is live")

	require.NoError(t, w.db.Model(&models.Project{}).Where("id = ?", w.projectB).
		Update("deleted_at", "2026-01-01 00:00:00").Error)

	code, ids = w.listProjectsAs(t, uid, "")
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, ids,
		"the grant survives the soft-delete, but the project is unreadable by id, so listing it would "+
			"be new disclosure rather than a consistency fix")
}
