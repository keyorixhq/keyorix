package core

// storage_read_class_grant_paths_invite_test.go — STORAGE-ERR-CLASS-2 item 2 (batch B).
//
// Member invite and access-request approval read the target project and role before
// they grant. A failed read was reported as "project N no longer exists" / "project N
// not found or deleted" / "unknown role", which the transports answered 409 / 500 /
// 400. It is now ErrStorageReadUnavailable; an absent project or role keeps its text.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStorageReadClass_GrantPaths_InviteAndApprove(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			admin := w.user()
			require.NoError(t, w.core.storage.AssignRole(ctx, admin.ID, w.role(true).ID, Scope{}))
			p := w.project()
			role := w.role(true)

			t.Run("invite member: role and project lookups", func(t *testing.T) {
				call := func() error {
					_, err := c.inviteMemberWithMode(ctx, p.ID, w.user().ID, role.Name, admin.ID, 0, "", false)
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetRoleByName", "unknown role", call), 1)
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetProject", "not found or deleted", call), 1)

				_, err := c.inviteMemberWithMode(ctx, p.ID, w.user().ID, "no-such-role", admin.ID, 0, "", false)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown role")
				_, err = c.inviteMemberWithMode(ctx, 9_999_999, w.user().ID, role.Name, admin.ID, 0, "", false)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "not found or deleted")
			})

			t.Run("approve access request: project and role lookups", func(t *testing.T) {
				fresh := func(projectID uint) *models.AccessRequest {
					req := &models.AccessRequest{ProjectID: projectID, UserID: w.user().ID, SuggestedRole: role.Name, State: AccessRequestPending, CreatedAt: time.Now()}
					require.NoError(t, w.db.Create(req).Error)
					return req
				}
				call := func() error {
					req := fresh(p.ID)
					_, err := c.approveAccessRequestWithExpiryLocked(ctx, p.ID, req.ID, admin.ID, 0, role.Name, 0)
					if IsStorageReadUnavailable(err) {
						var row models.AccessRequest
						require.NoError(t, w.db.First(&row, req.ID).Error)
						assert.Equal(t, AccessRequestPending, row.State, "a refused approve left the request pending")
					}
					return err
				}
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetProject", "no longer exists", call), 1)
				assert.GreaterOrEqual(t, sweepReadFault(t, faulty, "GetRoleByName", "unknown role", call), 1)

				gone := &models.AccessRequest{ProjectID: 9_999_999, UserID: w.user().ID, SuggestedRole: role.Name, State: AccessRequestPending, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(gone).Error)
				_, err := c.approveAccessRequestWithExpiryLocked(ctx, 9_999_999, gone.ID, admin.ID, 0, role.Name, 0)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "no longer exists")
				req := fresh(p.ID)
				_, err = c.approveAccessRequestWithExpiryLocked(ctx, p.ID, req.ID, admin.ID, 0, "no-such-role", 0)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "unknown role")
				_, err = c.approveAccessRequestWithExpiryLocked(ctx, p.ID, req.ID, admin.ID, 0, role.Name, 0)
				require.NoError(t, err, "the retried approve succeeds")
			})
		})
	}
}
