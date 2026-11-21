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
			{op: "accessrequest.bulk.approve", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				// Unknown request ids: before the gate every principal got a result
				// listing them as not found; a principal without GLOBAL roles.assign is
				// now refused before any item is looked at.
				return func(actor uint) error {
					_, err := w.c.BulkApproveAccessRequests(ctx, []uint{999999}, actor, 0)
					return err
				}
			}},
			{op: "accessrequest.bulk.reject", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				return func(actor uint) error {
					_, err := w.c.BulkRejectAccessRequests(ctx, []uint{999999}, actor, 0, "parity")
					return err
				}
			}},
		}
	})
}
