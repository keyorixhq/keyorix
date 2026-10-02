package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed is the
// regression test for #2419 (FuzzStorageFaultOperations input decoding, on
// current main, to op="REST POST /api/v1/invitations"
// fault=(method=SupersedeActiveSetupTokens, NthCall=1, kind=error)): a failed
// supersede+create of the setup token must never be reported the same way a
// benign delivery/config failure is (201 "created, link not delivered") --
// the prior active links were NOT actually invalidated, so the caller must
// get a distinguishable, fail-closed signal.
func TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected storage fault"),
	})

	inv, prov, err := c.InviteGlobalWithLink(ctx, "carol@example.com", "", nil, admin.ID, 0)

	require.Error(t, err, "a failed supersede+create must be reported as an error, not silently swallowed")
	assert.Nil(t, prov)
	require.NotNil(t, inv, "the invitation row itself was already committed by a separate, earlier call")
	assert.True(t, errors.Is(err, ErrSetupTokenIssuanceFailed),
		"the error must be distinguishable from a benign config/throttle/delivery failure so the HTTP layer can fail closed")

	// Confirm via a fresh, unfaulted read: no setup token was minted for this
	// subject at all -- the transaction genuinely rolled back, it did not
	// half-apply (e.g. superseding an old token while failing to create the
	// replacement, which would brick the invitee with no working link).
	n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "carol@example.com", c.now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance")
}

// TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed_Postgres
// is the real-Postgres sibling: the rollback this fix relies on is a nested
// WithTransaction (SAVEPOINT) inside IssueSetupToken, and SQLite's transaction
// semantics are not always a faithful proxy for Postgres's. Skips when
// KEYORIX_TEST_PG_DSN is unset.
func TestInviteGlobalWithLink_SupersedeActiveSetupTokensErrorFailsClosed_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgIsolatedSchemaDSN(t, base))
	require.NoError(t, kxstorage.MigrateExisting(db))
	st := store.NewLocalStorage(db)
	ctx := context.Background()

	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	c.SetCredentialDelivery(&fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}, testBaseURL)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "SupersedeActiveSetupTokens", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected storage fault"),
	})

	inv, prov, err := c.InviteGlobalWithLink(ctx, "carol@example.com", "", nil, admin.ID, 0)

	require.Error(t, err)
	assert.Nil(t, prov)
	require.NotNil(t, inv)
	assert.True(t, errors.Is(err, ErrSetupTokenIssuanceFailed))

	n, err := st.CountSetupTokensSince(ctx, SetupPurposeInvitationAccept, "carol@example.com", c.now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Zero(t, n, "no setup token should exist after a rolled-back issuance (Postgres)")
}
