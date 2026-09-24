package core

// End-to-end notification assertions against the real notifications table
// (newBootstrappedCore now migrates the production schema — see
// auth_bootstrap_rbac_test.go). notifications_test.go's existing coverage
// asserts the notify* helpers call CreateNotification with the right
// arguments against a MockStorage — that proves the helper builds the right
// row, but never proves a real caller flow actually reaches a persisted,
// readable notification, the same "return value looks fine either way" gap
// #391's own fix (TestRemoteStorageCreateNotification_ClosesTheFailsOpenLoop)
// closed for the fails-open notify path. These read the row back via
// st.ListNotifications after driving the real production entry point, the
// same way classification_gate_test.go's fixtures already do for the access
// gate itself.
//
// last-admin events (guardLastAdminDeactivation, guardLastProjectAdmin, and
// the group-path equivalents in authz.go) were checked and have no
// corresponding notify call anywhere in the codebase — they are a
// synchronous refusal (an error returned to the caller), not an
// asynchronously-notified event, so there is nothing to assert here. Filing
// "should a last-admin refusal alert other admins" as a product question is
// out of scope for this PR, which only adds coverage for notifications the
// code already promises.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeProjectApprover assigns roleName (must be one of approverRoleNames) to
// userID AT projectID's scope. ListProjectMembers — the query every
// "new request"/break-glass admin-alert fan-out reads from — matches on
// user_roles.project_id exactly (local_rbac.go), so a GLOBAL grant
// (storage.Scope{}, e.g. seedClassificationGateFixture's own admin approver)
// does not make a user a project member for notification purposes, even
// though it satisfies requireAdminAuthorityAt for approving.
func makeProjectApprover(t *testing.T, st *store.LocalStorage, userID, projectID uint, roleName string) {
	t.Helper()
	ctx := context.Background()
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, userID, role.ID, storage.Scope{ProjectID: projectID}))
}

// #2032: creating a secret-scoped access request alerts the project's
// approvers, and skips the requester themselves.
func TestSecretAccessRequest_CreateNotifiesProjectApprovers(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	makeProjectApprover(t, st, approverID, projectID, "project_admin")

	_, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it for an incident")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, approverID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "the project approver must be notified of the new secret-scoped request")
	assert.Equal(t, NotificationAccessRequested, notes[0].Type)
	assert.Contains(t, notes[0].Message, "db-password")

	own, err := st.ListNotifications(ctx, requesterID, false, 10)
	require.NoError(t, err)
	assert.Empty(t, own, "the requester is not notified of their own request")
}

// #2032: approving a secret-scoped access request notifies the requester.
func TestSecretAccessRequest_ApproveNotifiesRequester(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)

	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, requesterID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "the requester must be notified their secret-scoped request was approved")
	assert.Equal(t, NotificationAccessApproved, notes[0].Type)
	assert.Contains(t, notes[0].Message, "db-password")
}

// #2032: rejecting a secret-scoped access request (core.RejectAccessRequest,
// shared with the project/role family — see access_request_proxy.go's own
// doc comment) notifies the requester too.
func TestSecretAccessRequest_RejectNotifiesRequester(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it")
	require.NoError(t, err)

	_, err = c.RejectAccessRequest(ctx, projectID, req.ID, approverID, 0, "not justified")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, requesterID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "the requester must be notified their secret-scoped request was rejected")
	assert.Equal(t, NotificationAccessRejected, notes[0].Type)
}

// Break-glass activation alerts the project's admin-tier members
// (notifyBreakGlassAdmins).
func TestActivateBreakGlass_NotifiesProjectAdmins(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "break-glass-notify-test"})
	require.NoError(t, err)

	admin, err := st.CreateUser(ctx, foldedTestUser(t, "bg-admin", "bg-admin@example.com"))
	require.NoError(t, err)
	makeProjectApprover(t, st, admin.ID, proj.ID, "project_admin")

	actor, err := st.CreateUser(ctx, foldedTestUser(t, "bg-actor", "bg-actor@example.com"))
	require.NoError(t, err)
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actor.ID, viewerRole.ID, storage.Scope{ProjectID: proj.ID}))

	c.SetBreakGlassPolicy(BreakGlassPolicy{Enabled: true, EmergencyRole: "editor", DefaultTTL: time.Hour, MaxTTL: time.Hour})

	_, err = c.ActivateBreakGlass(ctx, proj.ID, actor.ID, "prod incident #42", "")
	require.NoError(t, err)

	notes, err := st.ListNotifications(ctx, admin.ID, false, 10)
	require.NoError(t, err)
	require.Len(t, notes, 1, "the project's admin approvers must be alerted of the break-glass activation")
	assert.Equal(t, EventBreakGlassActivated, notes[0].Type)
	assert.Contains(t, notes[0].Message, "editor")
}
