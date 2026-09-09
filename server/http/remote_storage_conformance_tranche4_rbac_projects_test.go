// remote_storage_conformance_tranche4_rbac_projects_test.go — issue #1808, tranche 4.
//
// Covers 18 methods from internal/storage/store/remote_rbac.go's Project/
// Environment catalog and group/machine RBAC-listing surface (#528/#525/#527):
//
//	DeleteEnvironment, DeleteProjectIfEmpty, GetEnvironment, GetProject,
//	ListEnvironments, ListEnvironmentsByProject,
//	ListEnvironmentsByProjectIncludingDeleted, ListProjectMachineRoleAssignments,
//	ListProjectMembers, ListProjectRoleAssignments, ListProjects,
//	ListProjectsWithCounts, AssignRoleToGroup, AssignRoleToGroupWithExpiry,
//	GetGroupRoleGrants, ListGroupRoleAssignments, ListConnectRefGrants,
//	ListConnectRefGrantsByConnector
//
// Every one of these is a thin server/http proxy handler (project_catalog_proxy.go,
// environment_catalog_proxy.go, rbac_role_grants_proxy.go, connect_grants_proxy.go)
// onto the SAME storage.Storage primitive LocalStorage itself implements — no
// intervening core business logic decides what the wire carries, so the field-
// exhaustive comparator is used wherever a full struct/list of structs comes back,
// per the shared harness's own stated purpose.
//
// Most of these read/list global or shared-scope state (h.ls and h.rs are two
// handles on the SAME backing database, per newConformanceHarness's own doc
// comment) — for that shape, seeding fixtures once (via h.ls or h.upstreamCore) and
// then comparing h.ls.M(x) against h.rs.M(x) directly on the SAME fixtures IS the
// correct, and simpler, comparison: there is no meaningful "local scenario" vs
// "remote scenario" split for a pure read of shared state, unlike a destructive or
// creating call where two independent target rows are needed to attribute an
// observed difference to one specific path. Each test's own comment says which
// shape it uses. newConformanceHarness's own bootstrapping (newTestCore) opens a
// brand-new isolated in-memory SQLite DB per test (server/http/integration_test.go's
// newTestCore, via uniqueMemDSN) — confirmed by reading that helper — so full-list
// equality (not just set-membership of this test's own fixtures) is safe throughout.
//
// Known gotcha applied below (AssignRoleToGroup / AssignRoleToGroupWithExpiry):
// h.rs's credential is a machine/node identity. AssignRoleToGroupWithExpiry proxies
// through POST /api/v1/system/rbac/assign-role-to-group-with-expiry
// (rbac_role_grants_proxy.go), which calls core.AssignGroupRoleWithExpiry with
// actorID()==0 (a machine caller has no UserID) and no core.WithSelfMachineGranter
// tag (that tag is only set by the human-facing, non-/system route) — so
// requireGranterHoldsRolePermissions (internal/core/authz.go) takes its
// "actorIsMachine but ctx carries no WithSelfMachineGranter tag: fail closed" branch
// for every permission the target role holds. A role with ZERO permissions makes
// that loop a no-op (nothing to iterate), so the call succeeds regardless — this is
// why both group-assignment tests below create a plain, zero-permission role rather
// than reusing "admin", exactly like tranche 3's AssignRoleWithExpiry/
// AssignMachineRole tests.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- small unexported matchers (list-membership helpers for this tranche only) ---

func findProjectByID(projects []*models.Project, id uint) *models.Project {
	for _, p := range projects {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func findEnvironmentByID(envs []*models.Environment, id uint) *models.Environment {
	for _, e := range envs {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func findProjectWithCountsByID(projects []coreStorage.ProjectWithCounts, id uint) *coreStorage.ProjectWithCounts {
	for i := range projects {
		if projects[i].ID == id {
			return &projects[i]
		}
	}
	return nil
}

func findGroupRoleGrantByRoleID(grants []*coreStorage.GroupRoleGrant, roleID uint) *coreStorage.GroupRoleGrant {
	for _, g := range grants {
		if g.ID == roleID {
			return g
		}
	}
	return nil
}

func findProjectMember(members []coreStorage.ProjectMember, userID, roleID uint) *coreStorage.ProjectMember {
	for i := range members {
		if members[i].UserID == userID && members[i].RoleID == roleID {
			return &members[i]
		}
	}
	return nil
}

func findConnectRefGrantByID(grants []*models.ConnectRefGrant, id uint) *models.ConnectRefGrant {
	for _, g := range grants {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// --- GetProject ---

func TestConformance_GetProject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	project, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-gp-project", "conformance test project", []string{"dev"})
	require.NoError(t, err)
	// Mutate two fields the wire struct carries (Description, RequireMFA) away from
	// their zero/default values -- a field silently dropped on the read side would
	// come back false/empty instead of the real persisted value.
	project.RequireMFA = true
	project.Description = "conformance get-project description"
	_, err = h.ls.UpdateProject(ctx, project)
	require.NoError(t, err)

	localOut, err := h.ls.GetProject(ctx, project.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetProject(ctx, project.ID)
	require.NoError(t, err, "RemoteStorage.GetProject must succeed for a project that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetProject (RemoteStorage vs LocalStorage, same row)", localOut, remoteOut, map[string]bool{})

	// Not-found precondition: both paths must fail, not silently return a zero-value project.
	_, localErr := h.ls.GetProject(ctx, 999999999)
	_, remoteErr := h.rs.GetProject(ctx, 999999999)
	assert.Error(t, localErr, "sanity: LocalStorage.GetProject must fail for a nonexistent id")
	assert.Error(t, remoteErr, "RemoteStorage.GetProject must fail for a nonexistent id, not report false success")
}

// --- ListProjects ---

func TestConformance_ListProjects(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Global listing over shared state (see package doc): seed once, compare both
	// handles against the SAME resulting rows.
	projectA, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lp-a", "project A", []string{"dev"})
	require.NoError(t, err)
	projectB, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lp-b", "project B", []string{"dev"})
	require.NoError(t, err)
	// A soft-deleted project must not appear in the list -- exercised as this
	// method's natural negative/precondition case (GORM's default deleted_at IS
	// NULL scope on Project applies to a plain Find with no explicit filter).
	deletedProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lp-deleted", "", []string{"dev"})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteProject(ctx, deletedProject.ID))

	localList, err := h.ls.ListProjects(ctx)
	require.NoError(t, err)
	remoteList, err := h.rs.ListProjects(ctx)
	require.NoError(t, err, "RemoteStorage.ListProjects must succeed")

	require.Len(t, remoteList, len(localList), "RemoteStorage.ListProjects must return exactly the same number of "+
		"rows as LocalStorage against the same backing store")
	assert.Nil(t, findProjectByID(localList, deletedProject.ID), "sanity: the soft-deleted project must be excluded locally")
	assert.Nil(t, findProjectByID(remoteList, deletedProject.ID),
		"the soft-deleted project must also be excluded from RemoteStorage's list")

	for _, want := range []*models.Project{projectA, projectB} {
		localEntry := findProjectByID(localList, want.ID)
		require.NotNil(t, localEntry, "sanity: %s must appear in LocalStorage's list", want.Name)
		remoteEntry := findProjectByID(remoteList, want.ID)
		require.NotNil(t, remoteEntry, "%s must appear in RemoteStorage's list", want.Name)
		assertFieldExhaustiveEqual(t, "ListProjects entry "+want.Name, localEntry, remoteEntry, map[string]bool{})
	}
}

// --- ListProjectsWithCounts ---

func TestConformance_ListProjectsWithCounts(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	live, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpwc-live", "", []string{"dev"})
	require.NoError(t, err)
	liveEnvs, err := h.ls.ListEnvironmentsByProject(ctx, live.ID)
	require.NoError(t, err)
	require.NotEmpty(t, liveEnvs)
	for i := 0; i < 2; i++ {
		_, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-lpwc-secret", ProjectID: live.ID, EnvironmentID: liveEnvs[0].ID, Type: "password",
		})
		require.NoError(t, err)
		// Names need not be unique across environments/projects in this schema, but
		// give each a distinct name anyway for clarity in failures.
	}

	deleted, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpwc-deleted", "", []string{"dev"})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteProject(ctx, deleted.ID))

	// include_deleted=false: the deleted project must be excluded on both paths,
	// and the live project's counts must round-trip exactly.
	localVisible, err := h.ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	remoteVisible, err := h.rs.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err, "RemoteStorage.ListProjectsWithCounts(false) must succeed")

	assert.Nil(t, findProjectWithCountsByID(localVisible, deleted.ID), "sanity: deleted project excluded locally")
	assert.Nil(t, findProjectWithCountsByID(remoteVisible, deleted.ID),
		"the soft-deleted project must also be excluded from RemoteStorage's include_deleted=false list")

	localLiveEntry := findProjectWithCountsByID(localVisible, live.ID)
	require.NotNil(t, localLiveEntry, "sanity: the live project must appear locally")
	require.EqualValues(t, 2, localLiveEntry.SecretCount, "sanity: local secret count")
	remoteLiveEntry := findProjectWithCountsByID(remoteVisible, live.ID)
	require.NotNil(t, remoteLiveEntry, "the live project must appear in RemoteStorage's list")
	assertFieldExhaustiveEqual(t, "ListProjectsWithCounts(false) live project", localLiveEntry, remoteLiveEntry, map[string]bool{})

	// include_deleted=true: the deleted project must now appear on both paths,
	// Deleted=true with a populated DeletedAt.
	localAll, err := h.ls.ListProjectsWithCounts(ctx, true)
	require.NoError(t, err)
	remoteAll, err := h.rs.ListProjectsWithCounts(ctx, true)
	require.NoError(t, err, "RemoteStorage.ListProjectsWithCounts(true) must succeed")

	localDeletedEntry := findProjectWithCountsByID(localAll, deleted.ID)
	require.NotNil(t, localDeletedEntry, "sanity: the deleted project must appear locally with include_deleted=true")
	assert.True(t, localDeletedEntry.Deleted, "sanity: local Deleted flag")
	remoteDeletedEntry := findProjectWithCountsByID(remoteAll, deleted.ID)
	require.NotNil(t, remoteDeletedEntry,
		"the deleted project must appear in RemoteStorage's include_deleted=true list, not stay hidden")
	assertFieldExhaustiveEqual(t, "ListProjectsWithCounts(true) deleted project", localDeletedEntry, remoteDeletedEntry, map[string]bool{})
}

// --- DeleteProjectIfEmpty ---

func TestConformance_DeleteProjectIfEmpty(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newEmptyProject := func(suffix string) *models.Project {
		p, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-dpie-empty-"+suffix, "", []string{"dev"})
		require.NoError(t, err)
		return p
	}
	newNonEmptyProject := func(suffix string) *models.Project {
		p, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-dpie-nonempty-"+suffix, "", []string{"dev"})
		require.NoError(t, err)
		envs, err := h.ls.ListEnvironmentsByProject(ctx, p.ID)
		require.NoError(t, err)
		require.NotEmpty(t, envs)
		_, err = h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-dpie-secret-" + suffix, ProjectID: p.ID, EnvironmentID: envs[0].ID, Type: "password",
		})
		require.NoError(t, err)
		return p
	}

	// Positive: an empty project is actually deleted, blockingSecretCount == 0.
	localEmpty := newEmptyProject("local")
	localBlocking, err := h.ls.DeleteProjectIfEmpty(ctx, localEmpty.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, localBlocking, "sanity: LocalStorage reports zero blocking secrets for a genuinely empty project")
	_, err = h.ls.GetProject(ctx, localEmpty.ID)
	assert.Error(t, err, "sanity: the local empty project must actually be gone")

	remoteEmpty := newEmptyProject("remote")
	remoteBlocking, err := h.rs.DeleteProjectIfEmpty(ctx, remoteEmpty.ID)
	require.NoError(t, err, "RemoteStorage.DeleteProjectIfEmpty must succeed for a genuinely empty project")
	assert.Equal(t, 0, remoteBlocking, "RemoteStorage must report zero blocking secrets for a genuinely empty project")
	_, err = h.ls.GetProject(ctx, remoteEmpty.ID)
	assert.Error(t, err, "the remote empty project must actually be gone server-side, not just report success")

	// Negative/precondition: a non-empty project must be REFUSED (blockingSecretCount
	// > 0, err == nil, project survives) -- not silently deleted anyway.
	localNonEmpty := newNonEmptyProject("local")
	localBlocking2, err := h.ls.DeleteProjectIfEmpty(ctx, localNonEmpty.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, localBlocking2, "sanity: LocalStorage reports the blocking secret count, not an error")
	_, err = h.ls.GetProject(ctx, localNonEmpty.ID)
	assert.NoError(t, err, "sanity: the local non-empty project must survive a refused delete-if-empty")

	remoteNonEmpty := newNonEmptyProject("remote")
	remoteBlocking2, err := h.rs.DeleteProjectIfEmpty(ctx, remoteNonEmpty.ID)
	require.NoError(t, err, "RemoteStorage.DeleteProjectIfEmpty must report the guard refusal via the return value, not an error")
	assert.Equal(t, 1, remoteBlocking2,
		"RemoteStorage must report the SAME blocking secret count the guard on the server actually computed")
	_, err = h.ls.GetProject(ctx, remoteNonEmpty.ID)
	assert.NoError(t, err, "the remote non-empty project must survive server-side -- a dropped guard would have deleted it anyway")
}

// --- GetEnvironment ---

func TestConformance_GetEnvironment(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	env, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-ge-env"})
	require.NoError(t, err)

	localOut, err := h.ls.GetEnvironment(ctx, env.ID)
	require.NoError(t, err)
	remoteOut, err := h.rs.GetEnvironment(ctx, env.ID)
	require.NoError(t, err, "RemoteStorage.GetEnvironment must succeed for an environment that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetEnvironment (RemoteStorage vs LocalStorage, same row)", localOut, remoteOut, map[string]bool{})

	_, localErr := h.ls.GetEnvironment(ctx, 999999999)
	_, remoteErr := h.rs.GetEnvironment(ctx, 999999999)
	assert.Error(t, localErr, "sanity: LocalStorage.GetEnvironment must fail for a nonexistent id")
	assert.Error(t, remoteErr, "RemoteStorage.GetEnvironment must fail for a nonexistent id, not report false success")
}

// --- DeleteEnvironment ---

func TestConformance_DeleteEnvironment(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newEmptyEnv := func(suffix string) *models.Environment {
		e, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-de-empty-" + suffix})
		require.NoError(t, err)
		return e
	}

	localEnv := newEmptyEnv("local")
	require.NoError(t, h.ls.DeleteEnvironment(ctx, localEnv.ID))
	_, err := h.ls.GetEnvironment(ctx, localEnv.ID)
	assert.Error(t, err, "sanity: the local environment must actually be gone")

	remoteEnv := newEmptyEnv("remote")
	require.NoError(t, h.rs.DeleteEnvironment(ctx, remoteEnv.ID),
		"RemoteStorage.DeleteEnvironment must succeed for an environment with no active secrets")
	_, err = h.ls.GetEnvironment(ctx, remoteEnv.ID)
	assert.Error(t, err, "the remote environment must actually be gone server-side, not just report success")

	// Negative/precondition: an environment with a live (active) secret must be
	// REFUSED on both paths, and must survive the refused attempt.
	newActiveEnv := func(suffix string) *models.Environment {
		e, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-de-active-" + suffix})
		require.NoError(t, err)
		_, err = h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-de-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: e.ID, Type: "password", Status: "active",
		})
		require.NoError(t, err)
		return e
	}

	localActiveEnv := newActiveEnv("local")
	assert.Error(t, h.ls.DeleteEnvironment(ctx, localActiveEnv.ID), "sanity: an environment with an active secret must refuse deletion")
	_, err = h.ls.GetEnvironment(ctx, localActiveEnv.ID)
	assert.NoError(t, err, "sanity: the local environment must survive a refused delete")

	remoteActiveEnv := newActiveEnv("remote")
	assert.Error(t, h.rs.DeleteEnvironment(ctx, remoteActiveEnv.ID),
		"RemoteStorage.DeleteEnvironment must refuse an environment with an active secret, not delete it anyway")
	_, err = h.ls.GetEnvironment(ctx, remoteActiveEnv.ID)
	assert.NoError(t, err, "the remote environment must survive server-side after a refused delete")
}

// --- ListEnvironments (global) ---

func TestConformance_ListEnvironments(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-le-other-project", "", nil)
	require.NoError(t, err)
	envA, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-le-a"})
	require.NoError(t, err)
	envB, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: otherProject.ID, Name: "conformance-le-b"})
	require.NoError(t, err)

	// Negative/precondition: a soft-deleted environment must be excluded from the
	// global list on both paths.
	deletedEnv, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-le-deleted"})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteEnvironment(ctx, deletedEnv.ID))

	localList, err := h.ls.ListEnvironments(ctx)
	require.NoError(t, err)
	remoteList, err := h.rs.ListEnvironments(ctx)
	require.NoError(t, err, "RemoteStorage.ListEnvironments must succeed")

	require.Len(t, remoteList, len(localList),
		"RemoteStorage.ListEnvironments must return exactly the same number of rows as LocalStorage")
	assert.Nil(t, findEnvironmentByID(localList, deletedEnv.ID), "sanity: the soft-deleted environment is excluded locally")
	assert.Nil(t, findEnvironmentByID(remoteList, deletedEnv.ID),
		"the soft-deleted environment must also be excluded from RemoteStorage's global list")

	for _, want := range []*models.Environment{envA, envB} {
		localEntry := findEnvironmentByID(localList, want.ID)
		require.NotNil(t, localEntry, "sanity: %s must appear locally", want.Name)
		remoteEntry := findEnvironmentByID(remoteList, want.ID)
		require.NotNil(t, remoteEntry, "%s must appear in RemoteStorage's global list", want.Name)
		assertFieldExhaustiveEqual(t, "ListEnvironments entry "+want.Name, localEntry, remoteEntry, map[string]bool{})
	}
}

// --- ListEnvironmentsByProject ---

func TestConformance_ListEnvironmentsByProject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	extraEnv, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: h.projectID, Name: "conformance-lebp-extra"})
	require.NoError(t, err)

	// Negative/precondition: an environment belonging to a DIFFERENT project must
	// not appear when listing h.projectID's environments -- the scope-drop risk
	// this method exists to catch.
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lebp-other-project", "", []string{"other"})
	require.NoError(t, err)

	localList, err := h.ls.ListEnvironmentsByProject(ctx, h.projectID)
	require.NoError(t, err)
	remoteList, err := h.rs.ListEnvironmentsByProject(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListEnvironmentsByProject must succeed")

	require.Len(t, remoteList, len(localList),
		"RemoteStorage.ListEnvironmentsByProject must return exactly the same number of rows as LocalStorage")
	assert.NotNil(t, findEnvironmentByID(localList, h.environmentID), "sanity: the harness's default env is included locally")
	assert.NotNil(t, findEnvironmentByID(remoteList, h.environmentID), "the harness's default env must be included remotely")
	assert.NotNil(t, findEnvironmentByID(localList, extraEnv.ID), "sanity: the extra env is included locally")
	remoteExtra := findEnvironmentByID(remoteList, extraEnv.ID)
	require.NotNil(t, remoteExtra, "the extra env must be included in RemoteStorage's project-scoped list")
	assertFieldExhaustiveEqual(t, "ListEnvironmentsByProject extra env", extraEnv, remoteExtra, map[string]bool{})

	otherEnvs, err := h.ls.ListEnvironmentsByProject(ctx, otherProject.ID)
	require.NoError(t, err)
	require.NotEmpty(t, otherEnvs)
	assert.Nil(t, findEnvironmentByID(localList, otherEnvs[0].ID),
		"sanity: the other project's environment must not leak into h.projectID's local listing")
	assert.Nil(t, findEnvironmentByID(remoteList, otherEnvs[0].ID),
		"the other project's environment must not leak into h.projectID's REMOTE listing either -- a "+
			"dropped/ignored project_id filter on the wire would return every environment instead of "+
			"scoping to the named project")
}

// --- ListEnvironmentsByProjectIncludingDeleted ---

func TestConformance_ListEnvironmentsByProjectIncludingDeleted(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	project, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lebpid-project", "", nil)
	require.NoError(t, err)
	liveEnv, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: project.ID, Name: "conformance-lebpid-live"})
	require.NoError(t, err)
	deletedEnv, err := h.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: project.ID, Name: "conformance-lebpid-deleted"})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteEnvironment(ctx, deletedEnv.ID))

	// Negative/precondition: the default (non-including-deleted) listing excludes
	// the soft-deleted environment on both paths -- the contrast this test exists
	// to establish against the "including deleted" variant below.
	localDefault, err := h.ls.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	remoteDefault, err := h.rs.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Nil(t, findEnvironmentByID(localDefault, deletedEnv.ID), "sanity: default listing excludes the deleted env locally")
	assert.Nil(t, findEnvironmentByID(remoteDefault, deletedEnv.ID), "default listing must also exclude the deleted env remotely")

	localAll, err := h.ls.ListEnvironmentsByProjectIncludingDeleted(ctx, project.ID)
	require.NoError(t, err)
	remoteAll, err := h.rs.ListEnvironmentsByProjectIncludingDeleted(ctx, project.ID)
	require.NoError(t, err, "RemoteStorage.ListEnvironmentsByProjectIncludingDeleted must succeed")

	require.Len(t, remoteAll, len(localAll), "RemoteStorage must return exactly the same rows as LocalStorage, deleted included")
	require.NotNil(t, findEnvironmentByID(localAll, liveEnv.ID), "sanity: the live env is present locally")
	require.NotNil(t, findEnvironmentByID(remoteAll, liveEnv.ID), "the live env must be present remotely")

	localDeletedEntry := findEnvironmentByID(localAll, deletedEnv.ID)
	require.NotNil(t, localDeletedEntry, "sanity: the soft-deleted env appears locally when including deleted")
	remoteDeletedEntry := findEnvironmentByID(remoteAll, deletedEnv.ID)
	require.NotNil(t, remoteDeletedEntry,
		"the soft-deleted env must appear in RemoteStorage's IncludingDeleted listing, not stay hidden")
	assert.True(t, remoteDeletedEntry.DeletedAt.Valid, "the wire round trip must preserve the DeletedAt timestamp, not just the row's existence")
	assertFieldExhaustiveEqual(t, "ListEnvironmentsByProjectIncludingDeleted deleted env", localDeletedEntry, remoteDeletedEntry, map[string]bool{})
}

// --- ListProjectMembers ---

func TestConformance_ListProjectMembers(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	member, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lpm-member", Email: "conformance-lpm-member@example.com",
		DisplayName: "Conformance Project Member", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRole(ctx, member.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID}))

	// Negative/precondition: a user with only an ENVIRONMENT-scoped grant (not
	// project-scope, environment_id=0) must NOT be reported as a project member --
	// ListProjectMembers.'s own doc comment restricts to environment_id = 0.
	envScopedUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lpm-envscoped", Email: "conformance-lpm-envscoped@example.com",
		DisplayName: "Conformance Env-Scoped User", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRole(ctx, envScopedUser.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}))

	localMembers, err := h.ls.ListProjectMembers(ctx, h.projectID)
	require.NoError(t, err)
	remoteMembers, err := h.rs.ListProjectMembers(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListProjectMembers must succeed")

	require.Len(t, remoteMembers, len(localMembers), "RemoteStorage.ListProjectMembers must return the same row count as LocalStorage")
	assert.Nil(t, findProjectMember(localMembers, envScopedUser.ID, role.ID), "sanity: the env-scoped user is not a project member locally")
	assert.Nil(t, findProjectMember(remoteMembers, envScopedUser.ID, role.ID),
		"the env-scoped user must also not be reported as a project member remotely -- a dropped "+
			"environment_id=0 filter on the wire would over-report project membership")

	localEntry := findProjectMember(localMembers, member.ID, role.ID)
	require.NotNil(t, localEntry, "sanity: the genuine project member appears locally")
	remoteEntry := findProjectMember(remoteMembers, member.ID, role.ID)
	require.NotNil(t, remoteEntry, "the genuine project member must appear in RemoteStorage's list")
	assertFieldExhaustiveEqual(t, "ListProjectMembers entry", localEntry, remoteEntry, map[string]bool{})
}

// --- ListProjectRoleAssignments ---

func TestConformance_ListProjectRoleAssignments(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	projectRole, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	globalRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lpra-user", Email: "conformance-lpra-user@example.com",
		DisplayName: "Conformance LPRA User", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRole(ctx, user.ID, projectRole.ID, coreStorage.Scope{ProjectID: h.projectID}))
	require.NoError(t, h.ls.AssignRole(ctx, user.ID, projectRole.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}))

	group, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-lpra-group"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, group.ID, projectRole.ID, coreStorage.Scope{ProjectID: h.projectID}))

	// Negative/precondition: a GLOBAL (project_id=0) grant for the SAME user must
	// be excluded -- ListProjectRoleAssignments's own doc comment says global
	// assignments are deliberately excluded (reviewed separately). Uses a
	// different role so it cannot be confused with the project-scope grant above.
	require.NoError(t, h.ls.AssignRole(ctx, user.ID, globalRole.ID, coreStorage.Scope{}))

	localAssignments, err := h.ls.ListProjectRoleAssignments(ctx, h.projectID)
	require.NoError(t, err)
	remoteAssignments, err := h.rs.ListProjectRoleAssignments(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListProjectRoleAssignments must succeed")

	assert.ElementsMatch(t, localAssignments, remoteAssignments,
		"RemoteStorage.ListProjectRoleAssignments must return exactly the same set of user+group grants as "+
			"LocalStorage against the same backing store")
	assert.False(t, containsRoleGrant(remoteAssignments, globalRole.ID, coreStorage.Scope{}),
		"a GLOBAL-scope grant must never appear in a project-scoped assignment listing -- a dropped project_id "+
			"filter on the wire would leak install-wide grants into a project's own access review")
	assert.True(t, containsRoleGrant(remoteAssignments, projectRole.ID, coreStorage.Scope{ProjectID: h.projectID}),
		"the project-scope user grant must be present remotely")
	assert.True(t, containsRoleGrant(remoteAssignments, projectRole.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}),
		"the environment-scope user grant must also be present remotely")
}

// --- ListProjectMachineRoleAssignments ---

func TestConformance_ListProjectMachineRoleAssignments(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	machine, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-lpmra-machine", core.MachineTypeService, "conformance test machine", "", h.adminUserID, 0)
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignMachineRole(ctx, machine.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID}))

	// Negative/precondition: a machine role grant scoped to a DIFFERENT project
	// must not leak into this project's listing -- the scope-drop risk this
	// method exists to catch.
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpmra-other-project", "", []string{"dev"})
	require.NoError(t, err)
	otherMachine, err := h.upstreamCore.CreateMachineIdentity(ctx, otherProject.ID, "conformance-lpmra-other-machine", core.MachineTypeService, "conformance test machine", "", h.adminUserID, 0)
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignMachineRole(ctx, otherMachine.ID, role.ID, coreStorage.Scope{ProjectID: otherProject.ID}))

	localAssignments, err := h.ls.ListProjectMachineRoleAssignments(ctx, h.projectID)
	require.NoError(t, err)
	remoteAssignments, err := h.rs.ListProjectMachineRoleAssignments(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListProjectMachineRoleAssignments must succeed")

	assert.ElementsMatch(t, localAssignments, remoteAssignments,
		"RemoteStorage.ListProjectMachineRoleAssignments must return exactly the same set as LocalStorage")
	assert.True(t, containsRoleGrant(remoteAssignments, role.ID, coreStorage.Scope{ProjectID: h.projectID}),
		"the genuine machine grant in h.projectID must be present remotely")
	assert.False(t, containsRoleGrant(remoteAssignments, role.ID, coreStorage.Scope{ProjectID: otherProject.ID}),
		"the other project's machine grant must not leak into h.projectID's remote listing")
}

// --- AssignRoleToGroup ---

func TestConformance_AssignRoleToGroup(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Zero-permission role -- see package doc comment for why.
	roleName, err := identity.NewFoldedName("conformance-artg-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}

	localGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-artg-local"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, localGroup.ID, role.ID, scope))

	remoteGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-artg-remote"})
	require.NoError(t, err)
	require.NoError(t, h.rs.AssignRoleToGroup(ctx, remoteGroup.ID, role.ID, scope),
		"RemoteStorage.AssignRoleToGroup must succeed for a zero-permission role grant")

	localAfter, err := h.ls.ListGroupRoleAssignments(ctx, localGroup.ID)
	require.NoError(t, err)
	remoteAfter, err := h.ls.ListGroupRoleAssignments(ctx, remoteGroup.ID)
	require.NoError(t, err)
	assert.True(t, containsRoleGrant(localAfter, role.ID, scope), "sanity: the local group grant is visible")
	assert.True(t, containsRoleGrant(remoteAfter, role.ID, scope),
		"the remote group grant must actually be visible server-side, not just report success")

	// Negative/precondition: assigning the SAME (group, role, scope) a second time
	// must fail on both paths ("already assigned"), not silently succeed a second
	// time and mask a dropped-scope defect as false idempotent success.
	assert.Error(t, h.ls.AssignRoleToGroup(ctx, localGroup.ID, role.ID, scope))
	assert.Error(t, h.rs.AssignRoleToGroup(ctx, remoteGroup.ID, role.ID, scope),
		"RemoteStorage.AssignRoleToGroup must refuse a duplicate assignment at the exact same scope")
}

// --- AssignRoleToGroupWithExpiry ---

func TestConformance_AssignRoleToGroupWithExpiry(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Zero-permission role -- see package doc comment for why: this method
	// proxies through the /system route, where requireGranterHoldsRolePermissions
	// fails closed for a machine actor with no WithSelfMachineGranter tag, UNLESS
	// the target role carries zero permissions (nothing to check).
	roleName, err := identity.NewFoldedName("conformance-artge-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: h.projectID}
	expiresAt := time.Now().Add(time.Hour).UTC()

	localGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-artge-local"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroupWithExpiry(ctx, localGroup.ID, role.ID, scope, expiresAt))

	remoteGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-artge-remote"})
	require.NoError(t, err)
	require.NoError(t, h.rs.AssignRoleToGroupWithExpiry(ctx, remoteGroup.ID, role.ID, scope, expiresAt),
		"RemoteStorage.AssignRoleToGroupWithExpiry must succeed for a zero-permission role grant")

	localAfter, err := h.ls.ListGroupRoleAssignments(ctx, localGroup.ID)
	require.NoError(t, err)
	remoteAfter, err := h.ls.ListGroupRoleAssignments(ctx, remoteGroup.ID)
	require.NoError(t, err)
	assert.True(t, containsRoleGrant(localAfter, role.ID, scope), "sanity: the local time-bound grant is visible pre-expiry")
	assert.True(t, containsRoleGrant(remoteAfter, role.ID, scope),
		"the remote time-bound grant must actually be visible server-side pre-expiry, not just report success")

	// Negative/precondition: a second assignment at the same (group, role, scope)
	// while the first is still live (not expired) must be refused on both paths.
	assert.Error(t, h.ls.AssignRoleToGroupWithExpiry(ctx, localGroup.ID, role.ID, scope, expiresAt))
	// AssignRoleToGroupWithExpiryProxy (unlike the human-facing AssignRoleToGroup
	// handler) has no "already assigned" -> 409 special-case, so this genuinely
	// surfaces as a 500 on the real server -- and the shared harness's h.rs (like
	// every conformance test's) defaults RetryAttempts to 3 with quadratic backoff
	// for any 5xx (internal/storage/remote/client.go's isRetryableError), which
	// would otherwise burn a real 1+4+9=14s here for no additional signal beyond
	// "an error occurred". A short per-call timeout lets the FIRST attempt (which
	// already reaches the real server and gets the real refusal) complete
	// normally, then cuts the retry loop's backoff sleep short via ctx.Done()
	// instead of waiting it out -- the assertion only needs SOME error, not the
	// specific one from a particular attempt.
	shortCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	assert.Error(t, h.rs.AssignRoleToGroupWithExpiry(shortCtx, remoteGroup.ID, role.ID, scope, expiresAt),
		"RemoteStorage.AssignRoleToGroupWithExpiry must refuse a duplicate assignment while the existing grant is still live")
}

// --- GetGroupRoleGrants ---

func TestConformance_GetGroupRoleGrants(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	permanentRole, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	expiringRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	group, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-ggrg-group"})
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, group.ID, permanentRole.ID, coreStorage.Scope{ProjectID: h.projectID}))
	// An EXPIRED grant: GetGroupRoleGrants (unlike ListGroupRoleAssignments) applies
	// no expiry filter at all -- it must still be reported, on both paths, so this
	// doubles as the precondition/negative case relative to that sibling method's
	// filtering behavior.
	pastExpiry := time.Now().Add(-time.Hour).UTC()
	require.NoError(t, h.ls.AssignRoleToGroupWithExpiry(ctx, group.ID, expiringRole.ID, coreStorage.Scope{ProjectID: h.projectID}, pastExpiry))

	localGrants, err := h.ls.GetGroupRoleGrants(ctx, group.ID)
	require.NoError(t, err)
	remoteGrants, err := h.rs.GetGroupRoleGrants(ctx, group.ID)
	require.NoError(t, err, "RemoteStorage.GetGroupRoleGrants must succeed")

	require.Len(t, remoteGrants, len(localGrants), "RemoteStorage.GetGroupRoleGrants must return the same row count as LocalStorage")
	localPermanent := findGroupRoleGrantByRoleID(localGrants, permanentRole.ID)
	require.NotNil(t, localPermanent, "sanity: the permanent grant appears locally")
	remotePermanent := findGroupRoleGrantByRoleID(remoteGrants, permanentRole.ID)
	require.NotNil(t, remotePermanent, "the permanent grant must appear in RemoteStorage's list")
	assertFieldExhaustiveEqual(t, "GetGroupRoleGrants permanent grant", localPermanent, remotePermanent, map[string]bool{})

	localExpired := findGroupRoleGrantByRoleID(localGrants, expiringRole.ID)
	require.NotNil(t, localExpired, "sanity: the EXPIRED grant still appears locally (no expiry filter on this method)")
	remoteExpired := findGroupRoleGrantByRoleID(remoteGrants, expiringRole.ID)
	require.NotNil(t, remoteExpired,
		"the EXPIRED grant must also still appear via RemoteStorage -- an over-eager expiry filter accidentally "+
			"added on the wire path would silently hide it")
	assertFieldExhaustiveEqual(t, "GetGroupRoleGrants expired grant", localExpired, remoteExpired, map[string]bool{})

	// Negative/precondition: a group with zero grants returns an empty list, not
	// an error.
	emptyGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-ggrg-empty"})
	require.NoError(t, err)
	remoteEmpty, err := h.rs.GetGroupRoleGrants(ctx, emptyGroup.ID)
	require.NoError(t, err, "RemoteStorage.GetGroupRoleGrants must succeed (empty) for a group with no grants")
	assert.Empty(t, remoteEmpty)
}

// --- ListGroupRoleAssignments ---

func TestConformance_ListGroupRoleAssignments(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	liveRole, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	expiredRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	group, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-lgra-group"})
	require.NoError(t, err)
	scope := coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}
	require.NoError(t, h.ls.AssignRoleToGroup(ctx, group.ID, liveRole.ID, scope))

	// Negative/precondition: an EXPIRED grant must be excluded here (contrast
	// with GetGroupRoleGrants above, which does not filter by expiry) --
	// ListGroupRoleAssignments's own doc comment says it excludes expired grants.
	pastExpiry := time.Now().Add(-time.Hour).UTC()
	require.NoError(t, h.ls.AssignRoleToGroupWithExpiry(ctx, group.ID, expiredRole.ID, scope, pastExpiry))

	localAssignments, err := h.ls.ListGroupRoleAssignments(ctx, group.ID)
	require.NoError(t, err)
	remoteAssignments, err := h.rs.ListGroupRoleAssignments(ctx, group.ID)
	require.NoError(t, err, "RemoteStorage.ListGroupRoleAssignments must succeed")

	assert.ElementsMatch(t, localAssignments, remoteAssignments,
		"RemoteStorage.ListGroupRoleAssignments must return exactly the same LIVE grant set as LocalStorage")
	assert.True(t, containsRoleGrant(remoteAssignments, liveRole.ID, scope), "the live grant must be present remotely")
	assert.False(t, containsRoleGrant(remoteAssignments, expiredRole.ID, scope),
		"the EXPIRED grant must be excluded from RemoteStorage's list -- a dropped expiry filter on the wire "+
			"would report a lapsed grant as still-live")

	// A group with zero grants returns an empty list, not an error.
	emptyGroup, err := h.upstreamCore.CreateGroup(ctx, h.adminUserID, &core.CreateGroupRequest{Name: "conformance-lgra-empty"})
	require.NoError(t, err)
	remoteEmpty, err := h.rs.ListGroupRoleAssignments(ctx, emptyGroup.ID)
	require.NoError(t, err, "RemoteStorage.ListGroupRoleAssignments must succeed (empty) for a group with no grants")
	assert.Empty(t, remoteEmpty)
}

// --- ListConnectRefGrants ---

func TestConformance_ListConnectRefGrants(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	grantA, err := h.ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: role.ID, Connector: "conformance-lcrg-connA", RefPrefix: "prod/"})
	require.NoError(t, err)
	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	grantB, err := h.ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID: role.ID, Connector: "conformance-lcrg-connB", RefPrefix: "staging/", ExpiresAt: &expiry,
	})
	require.NoError(t, err)

	localList, err := h.ls.ListConnectRefGrants(ctx)
	require.NoError(t, err)
	remoteList, err := h.rs.ListConnectRefGrants(ctx)
	require.NoError(t, err, "RemoteStorage.ListConnectRefGrants must succeed")

	require.Len(t, remoteList, len(localList), "RemoteStorage.ListConnectRefGrants must return the same row count as LocalStorage")
	for _, want := range []*models.ConnectRefGrant{grantA, grantB} {
		localEntry := findConnectRefGrantByID(localList, want.ID)
		require.NotNil(t, localEntry, "sanity: grant for connector %s appears locally", want.Connector)
		remoteEntry := findConnectRefGrantByID(remoteList, want.ID)
		require.NotNil(t, remoteEntry, "grant for connector %s must appear in RemoteStorage's list", want.Connector)
		assertFieldExhaustiveEqual(t, "ListConnectRefGrants entry "+want.Connector, localEntry, remoteEntry, map[string]bool{})
	}
}

// --- ListConnectRefGrantsByConnector ---

func TestConformance_ListConnectRefGrantsByConnector(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)

	target, err := h.ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: role.ID, Connector: "conformance-lcrgbc-target", RefPrefix: "prod/"})
	require.NoError(t, err)
	// Negative/precondition risk: a grant for a DIFFERENT connector must not leak
	// into a by-connector query for "target" -- the exact filter
	// connectRefAllowed's hot path depends on for deny-by-default correctness.
	_, err = h.ls.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{RoleID: role.ID, Connector: "conformance-lcrgbc-other", RefPrefix: "prod/"})
	require.NoError(t, err)

	localList, err := h.ls.ListConnectRefGrantsByConnector(ctx, "conformance-lcrgbc-target")
	require.NoError(t, err)
	remoteList, err := h.rs.ListConnectRefGrantsByConnector(ctx, "conformance-lcrgbc-target")
	require.NoError(t, err, "RemoteStorage.ListConnectRefGrantsByConnector must succeed")

	require.Len(t, remoteList, 1, "RemoteStorage.ListConnectRefGrantsByConnector must return exactly the one grant scoped to this connector")
	require.Len(t, localList, 1, "sanity: LocalStorage returns exactly the one grant scoped to this connector")
	assertFieldExhaustiveEqual(t, "ListConnectRefGrantsByConnector target grant", target, remoteList[0], map[string]bool{})

	// Negative/precondition: a connector with zero grants returns an empty list.
	emptyList, err := h.rs.ListConnectRefGrantsByConnector(ctx, "conformance-lcrgbc-nonexistent")
	require.NoError(t, err, "RemoteStorage.ListConnectRefGrantsByConnector must succeed (empty) for a connector with no grants")
	assert.Empty(t, emptyList)
}
