package core

// storage_read_class_membership_test.go — STORAGE-ERR-CLASS-1 item 2.
//
// Membership, invitation and access-request lifecycle: revoke / reject / withdraw
// / resend / approve folded ANY read error into "<thing> not found". A fault is now
// ErrStorageReadUnavailable and the same call retried after the fault clears
// succeeds; a true not-found and a cross-project mismatch stay one identical
// "not found" answer.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStorageReadClass_MembershipInvitationAccessRequest(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			other := w.project()
			admin := w.user()
			member := w.user()
			// A project-scoped bypass role so the actor passes roles.assign on p.
			require.NoError(t, w.core.storage.AssignRole(ctx, admin.ID, w.role(true).ID, Scope{ProjectID: p.ID}))

			t.Run("revoke membership", func(t *testing.T) {
				m := &models.ProjectMembership{ProjectID: p.ID, UserID: member.ID, Role: "viewer", State: MembershipInvited, InvitedAt: time.Now()}
				require.NoError(t, w.db.Create(m).Error)
				// Both reads in TransitionMembership (before and under the lock).
				for _, nth := range []int{1, 2} {
					faulty.Arm(&faultstorage.FaultSpec{Method: "GetProjectMembership", NthCall: nth, Kind: faultstorage.KindError, Err: assert.AnError})
					_, err := c.TransitionMembership(ctx, p.ID, m.ID, MembershipRevoked, admin.ID, false)
					require.True(t, faulty.Fired(), "read #%d must be reached", nth)
					requireReadFault(t, err)
					var row models.ProjectMembership
					require.NoError(t, w.db.First(&row, m.ID).Error)
					assert.Equal(t, MembershipInvited, row.State, "the revoke was never applied (read #%d)", nth)
				}
				faulty.Arm(nil)
				_, err := c.TransitionMembership(ctx, p.ID, m.ID, MembershipRevoked, admin.ID, false)
				require.NoError(t, err, "the retried revoke succeeds")
				var row models.ProjectMembership
				require.NoError(t, w.db.First(&row, m.ID).Error)
				assert.Equal(t, MembershipRevoked, row.State)
			})

			t.Run("membership: absent and cross-project are one answer", func(t *testing.T) {
				m := &models.ProjectMembership{ProjectID: p.ID, UserID: w.user().ID, Role: "viewer", State: MembershipInvited, InvitedAt: time.Now()}
				require.NoError(t, w.db.Create(m).Error)
				_, errGone := c.TransitionMembership(ctx, p.ID, 9_999_999, MembershipRevoked, admin.ID, false)
				_, errCross := c.TransitionMembership(ctx, other.ID, m.ID, MembershipRevoked, admin.ID, false)
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error())
				assert.Contains(t, errGone.Error(), "membership not found")
				assert.False(t, IsStorageReadUnavailable(errGone))
				assert.False(t, IsStorageReadUnavailable(errCross))
			})

			t.Run("revoke invitation", func(t *testing.T) {
				inv := &models.ProjectInvitation{ProjectID: p.ID, Email: w.name("inv") + "@example.com", Role: "viewer", State: InvitationPending, InvitedBy: admin.ID, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(inv).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetProjectInvitation", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				err := c.RevokeInvitation(ctx, p.ID, inv.ID, admin.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var row models.ProjectInvitation
				require.NoError(t, w.db.First(&row, inv.ID).Error)
				assert.Equal(t, InvitationPending, row.State)
				faulty.Arm(nil)
				require.NoError(t, c.RevokeInvitation(ctx, p.ID, inv.ID, admin.ID))
				require.NoError(t, w.db.First(&row, inv.ID).Error)
				assert.Equal(t, InvitationRevoked, row.State)

				errGone := c.RevokeInvitation(ctx, p.ID, 9_999_999, admin.ID)
				errCross := c.RevokeInvitation(ctx, other.ID, inv.ID, admin.ID)
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error())
				assert.False(t, IsStorageReadUnavailable(errGone))
			})

			t.Run("resend invitation", func(t *testing.T) {
				inv := &models.ProjectInvitation{ProjectID: p.ID, Email: w.name("resend") + "@example.com", Role: "viewer", State: InvitationPending, InvitedBy: admin.ID, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(inv).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetProjectInvitation", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err := c.ResendInvitationLink(ctx, p.ID, inv.ID, admin.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
			})

			t.Run("reject access request", func(t *testing.T) {
				req := &models.AccessRequest{ProjectID: p.ID, UserID: member.ID, SuggestedRole: "viewer", State: AccessRequestPending, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(req).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err := c.RejectAccessRequest(ctx, p.ID, req.ID, admin.ID, 0, "no")
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var row models.AccessRequest
				require.NoError(t, w.db.First(&row, req.ID).Error)
				assert.Equal(t, AccessRequestPending, row.State)
				faulty.Arm(nil)
				_, err = c.RejectAccessRequest(ctx, p.ID, req.ID, admin.ID, 0, "no")
				require.NoError(t, err)

				_, errGone := c.RejectAccessRequest(ctx, p.ID, 9_999_999, admin.ID, 0, "no")
				_, errCross := c.RejectAccessRequest(ctx, other.ID, req.ID, admin.ID, 0, "no")
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error())
				assert.False(t, IsStorageReadUnavailable(errGone))
			})

			t.Run("approve access request", func(t *testing.T) {
				req := &models.AccessRequest{ProjectID: p.ID, UserID: member.ID, SuggestedRole: "viewer", State: AccessRequestPending, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(req).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err := c.approveAccessRequestWithExpiryLocked(ctx, p.ID, req.ID, admin.ID, 0, "viewer", 0)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
			})

			t.Run("domain allowlist user lookup (onboarding grant path)", func(t *testing.T) {
				c.membershipDomainAllowlist = []string{"example.com"}
				defer func() { c.membershipDomainAllowlist = nil }()
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				err := c.domainAllowedForUser(ctx, member.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				faulty.Arm(nil)
				require.NoError(t, c.domainAllowedForUser(ctx, member.ID))
				err = c.domainAllowedForUser(ctx, 9_999_999)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "user not found")
			})

			t.Run("withdraw access request", func(t *testing.T) {
				req := &models.AccessRequest{ProjectID: p.ID, UserID: member.ID, SuggestedRole: "viewer", State: AccessRequestPending, CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(req).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetAccessRequest", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				err := c.WithdrawAccessRequest(ctx, req.ID, member.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				faulty.Arm(nil)
				require.NoError(t, c.WithdrawAccessRequest(ctx, req.ID, member.ID))

				errGone := c.WithdrawAccessRequest(ctx, 9_999_999, member.ID)
				errOther := c.WithdrawAccessRequest(ctx, req.ID, w.user().ID)
				require.Error(t, errGone)
				require.Error(t, errOther)
				assert.Equal(t, errGone.Error(), errOther.Error())
				assert.False(t, IsStorageReadUnavailable(errGone))
			})
		})
	}
}
