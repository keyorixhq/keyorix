package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInviteGlobalWithLink_ThrottleCountErrorPersistsNothing is the regression
// test for #2599 (FuzzStorageFaultOperations input "Lx0": op="REST POST
// /api/v1/invitations", fault=(method=CountSetupTokensSince, NthCall=1,
// kind=error), oracle (a), differing tables [SetupToken AuditEvent]). The
// resend throttle fails closed on a count error, as it must, but
// provisionInvitationSetupLink treated that like a real "limit reached" and
// committed the invitation with no setup token, which the HTTP layer reported
// as 201. A failed count is a storage fault: it must persist nothing (no
// invitation, no token, no audit), send nothing, and return a distinguishable
// error. Covers both throttle queries (NthCall 1 = the 24h cap, 2 = the min
// interval). A retry once the fault clears must succeed.
func TestInviteGlobalWithLink_ThrottleCountErrorPersistsNothing(t *testing.T) {
	t.Parallel()
	for _, nth := range []int{1, 2} {
		t.Run(fmt.Sprintf("NthCall=%d", nth), func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			admin, err := st.GetUserByEmail(ctx, "admin@example.com")
			require.NoError(t, err)
			deliverer := &fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}
			c.SetCredentialDelivery(deliverer, testBaseURL)
			db := st.DB()
			var auditBefore int64
			require.NoError(t, db.Model(&models.AuditEvent{}).Count(&auditBefore).Error)

			faulty := faultstorage.NewFaultyStorage(st, nil)
			c.storage = faulty
			faulty.Arm(&faultstorage.FaultSpec{
				Method: "CountSetupTokensSince", NthCall: nth, Kind: faultstorage.KindError,
				Err: errors.New("injected storage fault"),
			})

			inv, prov, err := c.InviteGlobalWithLink(ctx, "erin@example.com", "", nil, admin.ID, 0)
			require.Error(t, err, "the throttle must stay fail-closed on a count error")
			require.True(t, faulty.Fired(), "the armed fault must actually have fired")
			assert.True(t, errors.Is(err, ErrResendThrottleUnverifiable), "got: %v", err)
			assert.Nil(t, inv, "a storage fault must not leave a committed invitation behind")
			assert.Nil(t, prov)
			assert.False(t, deliverer.called, "no setup link may be sent when the throttle cannot be verified")

			// Effect, not return value: fresh unfaulted reads.
			assert.Zero(t, globalInvitationCountForEmail(t, st, "erin@example.com"), "no invitation row")
			n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "erin@example.com", c.now().Add(-24*time.Hour))
			require.NoError(t, err)
			assert.Zero(t, n, "no setup token")
			var auditAfter int64
			require.NoError(t, db.Model(&models.AuditEvent{}).Count(&auditAfter).Error)
			assert.Equal(t, auditBefore, auditAfter, "no audit event for something that did not happen")

			// Fault cleared (single-fire): the same invite now succeeds.
			inv2, prov2, err := c.InviteGlobalWithLink(ctx, "erin@example.com", "", nil, admin.ID, 0)
			require.NoError(t, err)
			require.NotNil(t, inv2)
			require.NotNil(t, prov2)
			assert.Equal(t, 1, globalInvitationCountForEmail(t, st, "erin@example.com"))
		})
	}
}

// TestInviteGlobalWithLink_ThrottleLimitReachedStillPersistsInvitation pins the
// other direction: a real throttle verdict (the count succeeded and says "wait")
// is a rate-limit condition, not a storage fault, so the invitation is still
// created and returned with the error, as before (#345's "caller can resend"
// contract). Without this, persisting nothing on EVERY throttle error would pass
// the test above while silently changing that contract.
func TestInviteGlobalWithLink_ThrottleLimitReachedStillPersistsInvitation(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	_, _, err = c.InviteGlobalWithLink(ctx, "frank@example.com", "", nil, admin.ID, 0)
	require.NoError(t, err)
	// Immediately again: the min-interval throttle refuses the link.
	inv, prov, err := c.InviteGlobalWithLink(ctx, "frank@example.com", "", nil, admin.ID, 0)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrResendThrottleUnverifiable), "a real throttle verdict is not a storage fault")
	assert.Nil(t, prov)
	require.NotNil(t, inv, "a throttled invite is still created so the caller can resend")
	assert.Equal(t, 2, globalInvitationCountForEmail(t, st, "frank@example.com"))
}
