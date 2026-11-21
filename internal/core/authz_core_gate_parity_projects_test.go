// authz_core_gate_parity_projects_test.go — #4161 item 3: the route gates of
// project restore, share revocation, global invitation and the bulk access-request
// decisions, decided in core. See authz_core_gate_parity_test.go for the fixture
// and the runner.
package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestCoreGateParity_ProjectsSharesInvitationsBulk(t *testing.T) {
	t.Parallel()
	runGateCases(t, func(w *parityWorld) []gateCase {
		ctx, t := w.ctx, w.t
		return []gateCase{
			{op: "invitation.global", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				return func(actor uint) error {
					_, _, err := w.c.InviteGlobalWithLink(ctx, "parity-inv-"+a+"@example.com", "system_viewer", nil, actor, 0)
					return err
				}
			}},
			{op: "project.restore", deniedBy: w.viewerB, allowedBy: w.admin, run: func(a string) func(uint) error {
				// A fresh soft-deleted project per attempt; viewerB holds project_viewer
				// at it (a real grant short of roles.assign).
				p, err := w.c.CreateProject(ctx, "parity-restore-"+a, "")
				require.NoError(t, err)
				require.NoError(t, w.st.AssignRole(ctx, w.viewerB, w.viewerRoleID, storage.Scope{ProjectID: p.ID}))
				require.NoError(t, w.st.DeleteProject(ctx, p.ID))
				return func(actor uint) error { return w.c.RestoreProject(ctx, actor, p.ID) }
			}},
			{op: "share.revoke", deniedBy: w.viewerA, allowedBy: w.admin, run: func(a string) func(uint) error {
				// The owner shares (owner authority) but holds no secrets.write role, so
				// the route gate refuses their own revocation; core now agrees.
				s := w.secret("share-"+a, w.envA1, w.viewerA)
				share, err := w.c.ShareSecret(ctx, &ShareSecretRequest{SecretID: s.ID, RecipientID: w.devA, Permission: "read", SharedBy: w.viewerA})
				require.NoError(t, err)
				return func(actor uint) error { return w.c.RevokeShare(ctx, share.ID, actor) }
			}},
		}
	})
}

// The bulk access-request decisions (accessrequest.bulk.approve / .reject) are NOT
// gated here: core applies the finer per-item rule (roles.assign at each request's
// project, the single-request ceiling) that also lets a machine approver act (#2495),
// while the router's gate is roles.assign at the GLOBAL scope. The differential
// classifies those two ops coreGateExcluded instead (server/authzdiff); see
// internal/core/bulk_access_requests.go.
