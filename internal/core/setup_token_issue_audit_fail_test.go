// setup_token_issue_audit_fail_test.go — AUDIT-DISCLOSURE-NOV-1 item 1 red/green proof.
//
// IssueSetupToken committed the token first and then wrote setup_token.issued,
// discarding that write's result: a refused audit append still returned the
// plaintext link (and the invitation path delivered it), so a working link to an
// account was handed out with no audit record. Both issuers now write the row in
// the mint's own transaction through a fail-closed target: no row, no token, no
// supersede of the subject's previous link, nothing delivered.
//
// The fault is a storage decorator on LogAuditEvent for that one event type,
// re-wrapped inside transactions (WrapTx), with no production hook.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const setupIssuedEvent = "setup_token.issued"

// faultSetupIssuedAudit fails (or panics) every LogAuditEvent of setup_token.issued,
// inside a transaction as well as outside one.
func faultSetupIssuedAudit(inner storage.Storage, panics bool) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		LogAuditEvent: func(next storage.Storage, ctx context.Context, event *models.AuditEvent) error {
			if event.EventType == setupIssuedEvent {
				if panics {
					panic("fault-injected: " + setupIssuedEvent + " audit write panicked")
				}
				return fmt.Errorf("fault-injected: %s audit write failed", setupIssuedEvent)
			}
			return next.LogAuditEvent(ctx, event)
		},
	})
}

func setupTokensFor(t *testing.T, st *store.LocalStorage, purpose, email string) int64 {
	t.Helper()
	n, err := st.CountSetupTokensSince(context.Background(), purpose, email, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	return n
}

func setupIssuedRows(t *testing.T, st *store.LocalStorage) int {
	t.Helper()
	et := setupIssuedEvent
	events, _, err := st.GetAuditLogs(context.Background(), &storage.AuditFilter{Action: &et, PageSize: 100})
	require.NoError(t, err)
	return len(events)
}

// TestIssueSetupToken_AuditWriteFails_NoTokenAndPriorLinkStaysLive: the subject has
// a live link; a reissue whose audit write fails returns no token, mints nothing,
// and does not supersede the live link.
func TestIssueSetupToken_AuditWriteFails_NoTokenAndPriorLinkStaysLive(t *testing.T) {
	t.Parallel()
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panics=%v", panics), func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			admin, err := st.GetUserByEmail(ctx, "admin@example.com")
			require.NoError(t, err)
			req := IssueSetupTokenRequest{
				Purpose: SetupPurposePasswordResetLink, SubjectEmail: "admin@example.com",
				SubjectUserID: &admin.ID,
			}
			prior, err := c.IssueSetupToken(ctx, req)
			require.NoError(t, err)
			rowsBefore := setupIssuedRows(t, st)

			c.storage = faultSetupIssuedAudit(st, panics)
			issued, err := c.IssueSetupToken(ctx, req)
			c.storage = st

			require.Error(t, err, "a setup token must not be handed out when its issuance was not recorded")
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			assert.Nil(t, issued)
			assert.NotContains(t, err.Error(), setupPrefix, "the error must not carry a token")
			assert.EqualValues(t, 1, setupTokensFor(t, st, req.Purpose, req.SubjectEmail),
				"nothing stays minted: only the prior token exists")
			_, err = c.ValidateSetupToken(ctx, prior.PlainToken, req.Purpose)
			require.NoError(t, err, "the rolled-back reissue must not have superseded the live link")
			assert.Equal(t, rowsBefore, setupIssuedRows(t, st))

			// Once the audit log accepts the row, the reissue goes through as before.
			again, err := c.IssueSetupToken(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, again)
			assert.Equal(t, rowsBefore+1, setupIssuedRows(t, st))
		})
	}
}

// TestInviteGlobalWithLink_SetupTokenAuditFails_NothingCreatedNothingDelivered: the
// invitation path mints in its own transaction; a failed setup_token.issued write
// rolls back the invitation and the token, and no link is delivered.
func TestInviteGlobalWithLink_SetupTokenAuditFails_NothingCreatedNothingDelivered(t *testing.T) {
	t.Parallel()
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panics=%v", panics), func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			admin, err := st.GetUserByEmail(ctx, "admin@example.com")
			require.NoError(t, err)
			d := &fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}
			c.SetCredentialDelivery(d, testBaseURL)

			c.storage = faultSetupIssuedAudit(st, panics)
			inv, prov, err := c.InviteGlobalWithLink(ctx, "erin@example.com", "", nil, admin.ID, 0)
			c.storage = st

			require.Error(t, err)
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			assert.ErrorIs(t, err, ErrSetupTokenIssuanceFailed, "the HTTP layer fails closed on this sentinel")
			assert.Nil(t, inv)
			assert.Nil(t, prov)
			assert.False(t, d.called, "no link may be delivered for an unrecorded issuance")
			assert.Zero(t, globalInvitationCountForEmail(t, st, "erin@example.com"))
			assert.Zero(t, setupTokensFor(t, st, SetupPurposeInvitationAccept, "erin@example.com"))
		})
	}
}
