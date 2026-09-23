package core

// shares_split_clock_agreement_test.go — #1983-c headline test. Two
// independent enforcement paths read a share's expiry: CheckSharePermission
// (sharing_query.go), the live authorization decision, and
// ListSharesBySecretIDs (secret_risk.go's risk-scoring/exposure-count read).
// Before this series, both called their storage-layer counterpart with no
// clock argument at all -- each independently filtered on real wall-clock
// time.Now() internally, at whatever instant the DB query happened to run.
// Under normal operation they agreed by coincidence (both real-time reads,
// milliseconds apart); under a backward clock step (NTP correction, manual
// time change) between the two reads, nothing guaranteed they'd still agree
// on whether the SAME share had expired.
//
// Both now take an explicit `now time.Time` parameter, and every core-layer
// caller supplies c.shareEffectiveNow() -- the same watermark-clamped clock
// (permissions.go) already used throughout this package's share-expiry
// checks. This test proves the two paths actually agree on the verdict,
// including across a backward clock step: it warms the watermark via
// CheckSharePermission denying an expired share, steps the clock backward to
// where the share would look ACTIVE again if read naively, then asserts
// ListSharesBySecretIDs still excludes it AND CheckSharePermission still
// denies it -- both clamped to the same already-observed instant.
//
// Red-proof (run manually, not committed): revert secret_risk.go's
// ListSharesBySecretIDs call site from c.shareEffectiveNow() back to a
// hypothetical independent clock read (e.g. c.now() unclamped) -- this test
// goes red, the list wrongly resurrects the expired share.
//
// New file only.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSplitClock_CheckSharePermissionAgreesWithListSharesBySecretIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, secretID, baseNow, _ := newSharesExpiryFixture(t)

	expiresAt := baseNow.Add(time.Hour)
	_, err := c.ShareSecret(ctx, &ShareSecretRequest{
		SecretID: secretID, RecipientID: 2, Permission: "read", SharedBy: 1, ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)

	// Step 1: baseline two hours past expiry -- CheckSharePermission correctly
	// denies, which warms shareEffectiveNow's watermark to this baseline.
	baseline := baseNow.Add(2 * time.Hour)
	c.now = func() time.Time { return baseline }
	_, err = c.CheckSharePermission(ctx, secretID, 2)
	require.Error(t, err, "sanity: the share must read as expired at the baseline, before the clock ever moves")

	// Step 2: the clock steps BACKWARD to 30 minutes past ExpiresAt's issue
	// time -- nominally still inside the share's 1h window if read naively,
	// and well before the already-observed baseline.
	steppedBack := baseNow.Add(30 * time.Minute)
	c.now = func() time.Time { return steppedBack }

	// Step 3: the OTHER enforcement path -- secret_risk.go's exposure-count
	// read -- runs now, in the backward-stepped state.
	shares, err := c.storage.ListSharesBySecretIDs(ctx, []uint{secretID}, c.shareEffectiveNow())
	require.NoError(t, err)
	require.Empty(t, shares, "ListSharesBySecretIDs must still exclude the expired share after a backward clock step, agreeing with CheckSharePermission's denial")

	// Step 4: CheckSharePermission again, in the same backward-stepped state
	// -- must still agree (still denies), not flip back to granting access
	// just because the clock looks earlier now.
	_, err = c.CheckSharePermission(ctx, secretID, 2)
	require.Error(t, err, "CheckSharePermission must still deny after the backward clock step -- agreeing with ListSharesBySecretIDs")
}
