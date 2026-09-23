// share_listing_split_clock_regression_test.go — #1983 investigation follow-up:
// before this fix, core.permissions.go's in-memory activeShares filter (and
// sharing_query.go's ListSharedSecrets) used the watermarked shareEffectiveNow,
// while the storage-layer SQL filter they operate on top of
// (internal/storage/store/local_sharing.go) called time.Now() directly — a
// "split clock in series." A host clock stepped BACKWARD (or, in a test, an
// injected clock set behind real wall-clock time) made the SQL layer EXCLUDE a
// share the in-memory filter — and the caller — would otherwise still consider
// active, since the SQL layer's over-restrictive real-time fetch never gave the
// in-memory filter a chance to see the row at all.
//
// The opposite direction — clock advanced FORWARD past expiry — was already
// covered by TestShareExpiry_Enforcement's "expired share denies" case
// (shares_expiry_test.go) and is unaffected by this bug: a forward-stepped
// injected clock only makes the SQL layer's real-time filter equally or MORE
// restrictive than the in-memory one, never less — so it was never the
// direction that could leak a false negative past the in-memory filter.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestShareListing_SplitClockAgreement_BackwardInjectedClock freezes the
// injected clock 2h BEHIND real time, and gives a share an ExpiresAt 1h
// behind real time — i.e. between the frozen clock and real "now"
// (frozen < ExpiresAt < real). Relative to the injected clock the share has
// NOT expired yet; relative to real wall-clock time it has. Both
// ListSharedSecrets (no in-memory filter at all — its correctness depends
// entirely on the storage layer using the right clock) and
// CheckSecretPermission must treat it as still active.
func TestShareListing_SplitClockAgreement_BackwardInjectedClock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID, now, db := newSharesExpiryFixture(t)

	frozen := now.Add(-2 * time.Hour)
	expiresAt := now.Add(-1 * time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: secretID, OwnerID: 1, RecipientID: 2, Permission: "read", ExpiresAt: &expiresAt,
	}).Error)
	c.now = func() time.Time { return frozen }

	shared, err := c.ListSharedSecrets(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, shared, 1, "a share not yet expired relative to this process's OWN injected "+
		"clock must be visible, regardless of what the real (unrelated) wall clock reads")

	_, err = c.CheckSecretPermission(ctx, secretID, 2, PermissionRead)
	assert.NoError(t, err, "the same share must still authorize a direct permission check")
}

// TestListSecretShares_SplitClockAgreement_BackwardInjectedClock is the
// ListSecretShares counterpart (permissions.go's activeShares in-memory
// filter, applied on top of the storage fetch) — same setup, asserting the
// share still appears in the secret's own share list.
func TestListSecretShares_SplitClockAgreement_BackwardInjectedClock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID, now, db := newSharesExpiryFixture(t)

	frozen := now.Add(-2 * time.Hour)
	expiresAt := now.Add(-1 * time.Hour)
	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: secretID, OwnerID: 1, RecipientID: 2, Permission: "read", ExpiresAt: &expiresAt,
	}).Error)
	c.now = func() time.Time { return frozen }

	shares, err := c.ListSecretShares(ctx, secretID)
	require.NoError(t, err)
	assert.Len(t, shares, 1, "a share not yet expired relative to this process's OWN injected "+
		"clock must survive activeShares' in-memory filter, regardless of what the real "+
		"(unrelated) wall clock reads")
}
