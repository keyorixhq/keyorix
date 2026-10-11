// project_service_list_scoped_machine_test.go — follow-up item 4's gRPC half.
//
// #2858 added three gRPC tests for ListProjects (scoped reader, no grant, global
// reader unchanged). Andrei's review named the gaps those three left, and all of them
// are cases where the HTTP side IS covered and gRPC was not — which is exactly the
// shape of divergence #2780 asked to avoid ("treat the two transports together"):
//
//   - a MACHINE identity (ADR-030) listing projects;
//   - "a grant on A never reveals B" asserted on this transport too, not inferred
//     from the HTTP test;
//   - an ENVIRONMENT-only grant, the sharp edge core.VisibleProjects re-authorizes
//     at the project scope for;
//   - a SOFT-DELETED project with a live grant.
//
// The machine case matters most of the four: GetReadableScopes resolves a machine's
// grants through GetMachineRoleScopes rather than GetUserRoleScopes (G33), so a
// machine is a genuinely different code path through VisibleProjects, not a variant
// of the user path. A test that only ever exercises users would not notice if that
// branch regressed.
package services

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// p2780MachineCtx builds a context carrying a machine actor the way the real
// interceptor does. THREE things have to line up, and omitting any one of them
// degrades silently to the user path:
//
//  1. UserContext.ActorType = ActorTypeMachine — this is what
//     UserContext.ActorKind()/PrincipalID() branch on (a FIELD, not the presence of
//     MachineIdentityID). Without it PrincipalID() returns UserID, which is 0.
//  2. UserContext.MachineIdentityID — the id PrincipalID() then returns.
//  3. core.WithActorType(ctx, ActorTypeMachine) on the CONTEXT —
//     core.GetReadableScopes derives the actor type from the context
//     (actorTypeFromContext), not from the actorType argument VisibleProjects was
//     handed, and it defaults to ActorTypeUser. Without it a machine's grants are
//     resolved through GetUserRoleScopes.
//
// Worth spelling out because the failure mode is a false negative, not an error: a
// half-tagged machine context yields principalID 0, zero scopes, and an EMPTY
// list — which reads as a bug in the listing rather than a bug in the fixture. Both
// of my first two attempts at this helper did exactly that. production sets all
// three in server/grpc/interceptors/auth.go (~:220).
func p2780MachineCtx(machineID uint) context.Context {
	actor := &interceptors.UserContext{
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: machineID,
	}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	return core.WithActorType(ctx, core.ActorTypeMachine)
}

// p2780SeedMachine creates an ACTIVE machine identity in project 1 and grants it
// secrets.read at the given scope (projectID 0 = global).
func p2780SeedMachine(t *testing.T, db *gorm.DB, machineID, roleID, projectID, environmentID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: machineID, ProjectID: 1, Name: "p2780-ci", State: core.MachineActive,
	}).Error)
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: "p2780-machine-reader"}).Error)
	// Permission id 1 is secrets.read, seeded by newSecretTestRig.
	require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machineID, RoleID: roleID, ProjectID: projectID, EnvironmentID: environmentID,
	}).Error)
}

func TestProjectService2780_MachineWithProjectScopedGrantSeesThatProjectOnly(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	// A second project the machine holds nothing on.
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2780-machine-other"}).Error)
	p2780SeedMachine(t, db, 500, 4500, 1, 0)

	ctx := p2780MachineCtx(500)
	resp, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err,
		"a project-scoped MACHINE must not be denied the listing either — its grants resolve through "+
			"GetMachineRoleScopes (G33), a different branch of VisibleProjects than the user path")
	assert.Equal(t, []uint{1}, p2780GRPCListIDs(t, resp), "exactly the project it holds a grant in")
}

func TestProjectService2780_MachineWithNoGrantSeesNothing(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2780-machine-other2"}).Error)
	// An active machine with NO role grant at all.
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: 501, ProjectID: 1, Name: "p2780-ci-ungranted", State: core.MachineActive,
	}).Error)

	ctx := p2780MachineCtx(501)
	resp, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, p2780GRPCListIDs(t, resp),
		"two projects exist and this machine is authorized for neither — an empty list, not a denial")
}

// TestProjectService2780_MachineGetsNoAdminBypass is the half that makes the machine
// path worth testing separately: a machine identity never receives the admin-role
// bypass a human with the same role would (ADR-030 / authz.go's adminRoleNames), so
// granting it an admin-tier role must NOT turn its listing into "everything".
func TestProjectService2780_MachineGetsNoAdminBypass(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2780-machine-other3"}).Error)
	// A bypass-marked role, granted to the machine at ONE project's scope.
	require.NoError(t, db.Create(&models.Role{
		ID: 4502, Name: "p2780-machine-adminish", BypassesPermissionChecks: true,
	}).Error)
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: 502, ProjectID: 1, Name: "p2780-ci-adminish", State: core.MachineActive,
	}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: 502, RoleID: 4502, ProjectID: 1,
	}).Error)

	ctx := p2780MachineCtx(502)
	resp, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	ids := p2780GRPCListIDs(t, resp)
	assert.NotContains(t, ids, uint(2),
		"a machine holding an admin-tier role at ONE project's scope must not thereby see every "+
			"project — machines get no admin bypass, and the listing must not be the one place that leaks it")
}

// TestProjectService2780_GrantOnANeverRevealsBOnThisTransport asserts on gRPC what
// #2858 asserted on HTTP. Stated separately rather than inferred: the two transports
// share core.VisibleProjects but not their own filtering loops, and #2780 exists
// because one transport was fixed and the other was not.
func TestProjectService2780_GrantOnANeverRevealsBOnThisTransport(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	uid, scoped, other := p2780GRPCScopedReader(t, db)

	resp, err := svc.ListProjects(authCtx(uid, "p2780-scoped"), &emptypb.Empty{})
	require.NoError(t, err)
	ids := p2780GRPCListIDs(t, resp)
	assert.Contains(t, ids, scoped)
	assert.NotContains(t, ids, other, "a grant on one project must never reveal another, on this transport too")
}

// TestProjectService2780_EnvironmentOnlyGrantDoesNotRevealTheProject is the sharp
// edge: GetUserRoleIDsAt matches `environment_id = 0 OR environment_id = <asked>`, so
// a grant at (project, environment) does NOT authorize the project scope, and the
// holder cannot GetProject it. Listing it would be new disclosure. Asserted here as
// well as on HTTP, with the precondition checked first.
func TestProjectService2780_EnvironmentOnlyGrantDoesNotRevealTheProject(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	const envOnlyRole = 4600
	require.NoError(t, db.Create(&models.User{ID: 78, Username: "p2780-envonly", Email: "p2780-envonly@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: envOnlyRole, Name: "p2780-env-only-reader"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: envOnlyRole, PermissionID: 1}).Error)
	// Environment 1 belongs to project 1 (seeded by newSecretTestRig).
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 78, RoleID: envOnlyRole, ProjectID: 1, EnvironmentID: 1,
	}).Error)

	ctx := authCtx(78, "p2780-envonly")
	// Precondition: GetProject really does refuse this caller, so the assertion
	// below is parity with the per-project read rather than an arbitrary choice.
	_, gerr := svc.GetProject(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, gerr, "an environment-only grant does not authorize the project scope")

	resp, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, p2780GRPCListIDs(t, resp),
		"so the listing must not surface the parent project either")
}

// TestProjectService2780_SoftDeletedProjectIsNotListed closes the last gap. A
// project-scoped grant deliberately survives a soft-delete, and GetUserRoleScopes
// does not filter deleted projects — but GetProject 404s on one, so a scoped reader
// cannot read it through any path and must not see it listed. (On HTTP the same
// property is enforced by ?include_deleted=true staying global-only; this transport
// has no include_deleted parameter at all, so the whole question is "is it filtered",
// and the answer must be yes.)
func TestProjectService2780_SoftDeletedProjectIsNotListed(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	uid, scoped, _ := p2780GRPCScopedReader(t, db)

	// Control: live, it is listed.
	resp, err := svc.ListProjects(authCtx(uid, "p2780-scoped"), &emptypb.Empty{})
	require.NoError(t, err)
	require.Equal(t, []uint{scoped}, p2780GRPCListIDs(t, resp), "fixture control: listed while live")

	require.NoError(t, db.Model(&models.Project{}).Where("id = ?", scoped).
		Update("deleted_at", time.Now().UTC()).Error)

	resp, err = svc.ListProjects(authCtx(uid, "p2780-scoped"), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, p2780GRPCListIDs(t, resp),
		"the grant survives the soft-delete but the project is unreadable, so it must not be listed")
}
