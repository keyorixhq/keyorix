package services

// AUDIT-503-MAP-1: a security-relevant mutation whose audit row cannot be recorded
// (core.ErrMutationAuditUnavailable: the transaction rolled back, nothing changed)
// answers codes.Unavailable with the sentinel's fixed message and an ErrorInfo
// (reason audit_unavailable), not Internal. The audit store is made to refuse rows
// by a trigger, so the real storage path fails exactly as an unavailable audit store
// would. The REST twin is server/http/audit_unavailable_router_test.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

const auditOutageMessage = "could not record the change in the audit log; nothing was changed, retry"

func TestAuditOutage_RPCsAnswerUnavailable(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin (global)

	groups, projects, users, roles := NewGroupService(h.CoreService), NewProjectService(h.CoreService),
		NewUserService(h.CoreService), NewRoleService(h.CoreService)
	ctx := authCtx(1, "admin", "users.read", "users.write", "roles.assign", "roles.write", "secrets.write")

	cases := []struct {
		name  string
		call  func() error
		count func() int64
	}{
		{"CreateGroup",
			func() error {
				_, err := groups.CreateGroup(ctx, &pb.CreateGroupRequest{Name: "outage-group"})
				return err
			},
			func() int64 { return countModel(t, h, &models.Group{}) }},
		{"CreateProject",
			func() error {
				_, err := projects.CreateProject(ctx, &pb.CreateProjectRequest{Name: "outage-project"})
				return err
			},
			func() int64 { return countModel(t, h, &models.Project{}) }},
		{"CreateUser",
			func() error {
				_, err := users.CreateUser(ctx, &pb.CreateUserRequest{
					Username: "outage-user", Email: "outage-user@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
				})
				return err
			},
			func() int64 { return countModel(t, h, &models.User{}) }},
		{"CreateRole",
			func() error {
				_, err := roles.CreateRole(ctx, &pb.CreateRoleRequest{
					Name: "outage-role", Description: "d", Permissions: []string{"secrets.read"},
				})
				return err
			},
			func() int64 { return countModel(t, h, &models.Role{}) }},
	}

	require.NoError(t, h.DB.Exec(
		`CREATE TRIGGER refuse_all_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`).Error)
	t.Cleanup(func() { require.NoError(t, h.DB.Exec(`DROP TRIGGER IF EXISTS refuse_all_audit`).Error) })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.count()
			err := tc.call()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, err)
			assert.Equal(t, codes.Unavailable, st.Code(), err.Error())
			assert.Equal(t, auditOutageMessage, st.Message(), "the sentinel's fixed text, never the wrapped cause")
			var info *errdetails.ErrorInfo
			for _, d := range st.Details() {
				if ei, ok := d.(*errdetails.ErrorInfo); ok {
					info = ei
				}
			}
			require.NotNil(t, info, "an ErrorInfo detail carries the stable reason")
			assert.Equal(t, "audit_unavailable", info.GetReason())
			assert.Equal(t, before, tc.count(), "nothing was changed")
		})
	}
}

func countModel(t *testing.T, h *testhelper.RBACTestHelper, model any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, h.DB.Model(model).Count(&n).Error)
	return n
}
