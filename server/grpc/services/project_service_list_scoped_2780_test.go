// project_service_list_scoped_2780_test.go — #2780 on the gRPC transport.
//
// #2780 asked explicitly for both transports to get the SAME decision rather than
// a divergent one. ProjectService.ListProjects had the identical defect to the HTTP
// route: authorizeGlobal(secrets.read) followed by an unfiltered list, so a caller
// whose only grants are project-scoped got PermissionDenied while being able to
// read those same projects one at a time through GetProject.
//
// The regression test is ..._ProjectScopedReaderSeesTheirProject (red before,
// green after). The other two are the invariants that must hold before AND after:
// a caller with no grant sees nothing, and a global reader's list is unchanged.
package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// p2780GRPCScopedReader seeds a second project and a user holding secrets.read ONLY
// at the first project's scope, returning (userID, scopedProjectID,
// otherProjectID). The rig's own user 1 keeps its global writer grant, so the
// "global reader unchanged" assertion has something to compare against.
func p2780GRPCScopedReader(t *testing.T, db *gorm.DB) (userID, scopedProject, otherProject uint) {
	t.Helper()
	const scopedRoleID = 4242
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "p2780-billing"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 77, Username: "p2780-scoped", Email: "p2780-scoped@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: scopedRoleID, Name: "p2780-project-viewer"}).Error)
	// Permission id 1 is secrets.read, seeded by newSecretTestRig.
	require.NoError(t, db.Create(&models.RolePermission{RoleID: scopedRoleID, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 77, RoleID: scopedRoleID, ProjectID: 1}).Error)
	return 77, 1, 2
}

func p2780GRPCListIDs(t *testing.T, resp *pb.ListProjectsResponse) []uint {
	t.Helper()
	ids := make([]uint, 0, len(resp.GetProjects()))
	for _, p := range resp.GetProjects() {
		ids = append(ids, uint(p.GetId()))
	}
	return ids
}

// TestProjectService2780_ProjectScopedReaderSeesTheirProject is the regression.
func TestProjectService2780_ProjectScopedReaderSeesTheirProject(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	uid, scoped, other := p2780GRPCScopedReader(t, db)

	resp, err := svc.ListProjects(authCtx(uid, "p2780-scoped"), &emptypb.Empty{})
	require.NoError(t, err,
		"a project-scoped reader must not get PermissionDenied from the project listing (#2780) — "+
			"they can already read this project through GetProject")
	ids := p2780GRPCListIDs(t, resp)
	assert.Equal(t, []uint{scoped}, ids, "exactly the project they hold a grant in")
	assert.NotContains(t, ids, other, "a grant on one project must never reveal another")
}

// TestProjectService2780_NoGrantsSeesNothing — must hold before and after. User 999
// holds nothing; the world has two projects, so the empty result is meaningful.
func TestProjectService2780_NoGrantsSeesNothing(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	p2780GRPCScopedReader(t, db) // make the world non-empty

	resp, err := svc.ListProjects(authCtx(999, "p2780-nobody"), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, p2780GRPCListIDs(t, resp), "a caller with no project grant must see no project")
}

// TestProjectService2780_GlobalReaderListUnchanged — the no-loss half. The rig's
// user 1 holds the writer role globally, so it is authorized at Scope{} and the
// list is not filtered at all.
func TestProjectService2780_GlobalReaderListUnchanged(t *testing.T) {
	svc, db := newProjectTestRigWithDB(t)
	_, scoped, other := p2780GRPCScopedReader(t, db)

	resp, err := svc.ListProjects(authCtx(1, "owner"), &emptypb.Empty{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{scoped, other}, p2780GRPCListIDs(t, resp),
		"a global reader must still see every project — the fix narrows for scoped callers only")
}
