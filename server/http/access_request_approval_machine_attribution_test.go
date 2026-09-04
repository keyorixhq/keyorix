// access_request_approval_machine_attribution_test.go — Part 2 regression
// audit finding on PR #1622: the dual-control machine-approver discriminator
// fields (AccessRequestApproval.ApproverMachineIdentityID,
// AccessRequest.ResolvedByMachineIdentityID) were added to the model and to
// LocalStorage's direct call sites, but never threaded through the
// storage.type:remote wire structs (accessRequestApprovalWire/
// accessRequestWire in internal/storage/store/remote_invitations.go) or the
// server/hub-side proxy handlers (CreateAccessRequestApprovalProxy,
// UpdateAccessRequestProxy in server/http/handlers/access_request_proxy.go).
// A machine caller's principal ID was being written into the USER-scoped
// ApproverID/ResolvedBy column instead, reopening the exact false-collision
// bug #1622 fixed for LocalStorage callers, for any storage.type:remote
// deployment or any machine caller reaching these proxy routes directly.
package http

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
)

func TestCreateAccessRequestApprovalProxy_MachineApproverAttributedToMachineIdentityID(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, testCore)
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectID := projects[0].ID

	// A permission-less role so the approval ceiling (RequireGranterHoldsRolePermissions)
	// passes trivially -- this test's subject is attribution, not the ceiling.
	targetRoleName, err := identity.NewFoldedName("machine-attribution-target-role")
	require.NoError(t, err)
	_, err = testCore.Storage().CreateRole(ctx, targetRoleName, "")
	require.NoError(t, err)

	requester, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "machine-attribution-requester", Email: "machine-attribution-requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	req, err := testCore.RequestProjectAccess(ctx, projectID, requester.ID, "machine-attribution-target-role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	mi, err := testCore.CreateMachineIdentity(ctx, projectID, "machine-attribution-approver", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)

	systemWriteRoleName, err := identity.NewFoldedName("machine-attribution-system-writer")
	require.NoError(t, err)
	role, err := testCore.Storage().CreateRole(ctx, systemWriteRoleName, "")
	require.NoError(t, err)
	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID uint
	for _, p := range perms {
		if p.Name == "system.write" {
			systemWriteID = p.ID
		}
	}
	require.NotZero(t, systemWriteID)
	require.NoError(t, testCore.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID, false))
	require.NoError(t, testCore.Storage().AssignMachineRole(ctx, mi.ID, role.ID, coreStorage.Scope{}))

	tok, err := testCore.IssueMachineToken(ctx, projectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "machine-attribution-token"})
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	httpReq, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/system/access-requests/%d/approvals", server.URL, req.ID),
		bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer "+tok.PlainToken)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a machine identity holding role-grant authority over the target role must be able to approve")

	approvals, err := testCore.Storage().ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	require.Len(t, approvals, 1)
	require.Equal(t, mi.ID, approvals[0].ApproverMachineIdentityID, "the machine approver's ID must be recorded in ApproverMachineIdentityID")
	require.Zero(t, approvals[0].ApproverID, "ApproverID (the USER-scoped column) must NOT receive the machine's principal ID")
}
