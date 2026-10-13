// secret_readable_listing_f1_f2_test.go — the two blockers the coordinator's
// review of #2874 raised.
//
// F1: every truncation signal in this package was inert at the shipped
// configuration. convertToStorageFilter hard-codes the storage page size to
// secretListingMaxRows (10000) and discards the caller's paging, and
// ListSecretsInScope threw away storage's pre-LIMIT COUNT(*) into `_` and then
// derived Total from the already-clamped row count. So len(Secrets) == Total
// always held, nothing downstream could detect a short count, and a scope
// holding more than 10000 secrets returned exactly 10000 with
// Truncated == false — TOTAL SECRETS reading a confidently-wrong floor with
// Degraded == false, which is the defect class #2780 exists to remove.
//
// The three pre-existing truncation tests passed only because they lowered
// unionPageSizeOverride to 4/10/4/50/4 — every value below the 10000 clamp that
// actually shadowed the bound they thought they were driving. Which is the same
// "a bound nobody has watched behave" failure those tests were written to
// prevent, one layer down. So the storage bound is injectable now too
// (listingMaxRowsOverride) and these tests drive it.
//
// F2: tier 1's switch to ListSecretsInScopeWithSharingInfo regressed two
// documented, parsed query params, because the sharing-dependent filters were
// evaluated before the sharing metadata was attached — see
// secretPassesSharingFilters.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// grantGlobalRead gives user 1 secrets.read at Scope{} — tier 1 of
// ListReadableSecrets.
func grantGlobalRead(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
}

// ── F1 ──────────────────────────────────────────────────────────────────────

// TestListReadableSecrets_StorageRowBoundIsReportedAsTruncation is F1's
// regression, driven at the bound that is actually in force.
//
// RED before the fix: Truncated == false and Total == 3 (the clamped row count),
// i.e. a floor presented as an exact count. The assertion that fails first is
// the one on Truncated; Total == 3 is reported either way and is the point —
// the number is not wrong-looking, which is why this was invisible.
func TestListReadableSecrets_StorageRowBoundIsReportedAsTruncation(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	grantGlobalRead(t, db)

	// The STORAGE bound, not the union bound: tier 1 takes a single
	// unscoped query, so the union page size is not even consulted.
	c.listingMaxRowsOverride = 3

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1, &models.SecretListFilter{Page: 1, PageSize: 20})
	require.NoError(t, err)

	assert.True(t, resp.Truncated,
		"the storage row bound cut 9 secrets down to 3, so the total is a FLOOR and the response must say so; "+
			"got Truncated=false with Total=%d", resp.Total)
	assert.NotEmpty(t, resp.TruncatedReason, "a truncation flag with no reason tells an operator nothing")
	assert.Equal(t, int64(3), resp.Total, "the clamped count itself is unchanged — what changes is that it is now labelled")
}

// TestListReadableSecrets_NotTruncatedWhenTheStorageBoundIsNotHit is the
// calibration. Without it, a mutation that set Truncated unconditionally would
// pass the test above, and every listing would claim to be a floor — which is
// just as useless as the silent version, in the other direction.
func TestListReadableSecrets_NotTruncatedWhenTheStorageBoundIsNotHit(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	grantGlobalRead(t, db)

	c.listingMaxRowsOverride = 50 // comfortably above 9

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1, &models.SecretListFilter{Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.False(t, resp.Truncated, "nothing was cut short, so nothing may be labelled a floor")
	assert.Empty(t, resp.TruncatedReason)
	assert.Equal(t, int64(9), resp.Total)
}

// TestListReadableSecrets_StorageBoundTruncationSurvivesTheInMemoryFilters pins
// that the truncation signal is keyed off the STORAGE clamp and not off the
// post-filter total. An in-memory search filter legitimately shrinks the set, so
// `Total < storageTotal` is normal — keying the flag on that comparison instead
// would raise it on every filtered query, which is the cheap wrong fix.
func TestListReadableSecrets_StorageBoundTruncationSurvivesTheInMemoryFilters(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	grantGlobalRead(t, db)
	c.listingMaxRowsOverride = 50 // NOT hit

	search := "a-01" // names are a-00..a-08, so this matches exactly one
	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20, Search: &search})
	require.NoError(t, err)
	assert.Less(t, resp.Total, int64(9), "the search filter must have shrunk the set, or this test proves nothing")
	assert.False(t, resp.Truncated,
		"an in-memory filter narrowing the result is not truncation — only the storage bound is")
}

// TestCountReadableSecrets_NonExactOnStorageRowBound carries F1 through to the
// consumer that matters: GetDashboardStats degrades TOTAL SECRETS on a non-exact
// count, and before this fix the storage bound could never produce one — so the
// dashboard rendered a floor as a count with Degraded == false.
func TestCountReadableSecrets_NonExactOnStorageRowBound(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	grantGlobalRead(t, db)

	c.listingMaxRowsOverride = 3
	_, exact, err := c.CountReadableSecrets(context.Background(), 1, 1)
	require.NoError(t, err)
	assert.False(t, exact, "a count taken from a storage-clamped listing is not exact")

	c.listingMaxRowsOverride = 50
	total, exact, err := c.CountReadableSecrets(context.Background(), 1, 1)
	require.NoError(t, err)
	assert.True(t, exact, "an unclamped listing yields an exact count")
	assert.Equal(t, int64(9), total)
}

// ── F2 ──────────────────────────────────────────────────────────────────────

// seedOwnedAndSharedForReader gives user 1 one OWNED secret and one secret owned
// by someone else and SHARED with them, in a project user 1 can read globally.
// Returns the two secret names.
func seedOwnedAndSharedForReader(t *testing.T, db *gorm.DB) (owned, shared string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 100, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "other", Email: "other@example.com"}).Error)

	ownedSecret := &models.SecretNode{
		Name: "mine", ProjectID: 1, EnvironmentID: 100, IsSecret: true,
		CreatedBy: "reader", OwnerID: 1,
	}
	require.NoError(t, db.Create(ownedSecret).Error)
	sharedSecret := &models.SecretNode{
		Name: "theirs", ProjectID: 1, EnvironmentID: 100, IsSecret: true,
		CreatedBy: "other", OwnerID: 2,
	}
	require.NoError(t, db.Create(sharedSecret).Error)
	// A third secret, neither owned nor shared — visible to user 1 only via the
	// global role. It is what makes show_owned_only/show_shared_only meaningful.
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "neither", ProjectID: 1, EnvironmentID: 100, IsSecret: true,
		CreatedBy: "other", OwnerID: 2,
	}).Error)

	require.NoError(t, db.Create(&models.ShareRecord{
		SecretID: sharedSecret.ID, RecipientID: 1, OwnerID: 2, Permission: "read",
	}).Error)
	return ownedSecret.Name, sharedSecret.Name
}

func listedNames(resp *models.SecretListResponse) []string {
	out := make([]string, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		out = append(out, s.Name)
	}
	return out
}

// TestListReadableSecrets_ShowSharedOnlyStillWorksForAGlobalReader is F2's first
// half.
//
// RED before the fix: total 0 and an empty list. ListSecretsInScope built each
// row as a bare &SecretWithSharingInfo{SecretNode: secret} and then ran
// secretPassesFilters, whose `filter.ShowSharedOnly && !s.IsShared` evaluated
// IsShared while it was still the zero value — so the filter dropped
// EVERYTHING. A caller lost a view they legitimately had, and the only existing
// coverage asserted `!= 401`, which is why CI was green.
func TestListReadableSecrets_ShowSharedOnlyStillWorksForAGlobalReader(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	_, shared := seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20, ShowSharedOnly: true})
	require.NoError(t, err)

	require.Equal(t, []string{shared}, listedNames(resp),
		"?show_shared_only=true must return exactly the shared secret; got %v (Total=%d)", listedNames(resp), resp.Total)
	assert.Equal(t, int64(1), resp.Total, "Total must describe the filtered set, not the pre-filter one")
}

// TestListReadableSecrets_ShowOwnedOnlyStillWorksForAGlobalReader is F2's second
// half, and the worse direction of the two: ShowOwnedOnly was not checked in
// secretPassesFilters AT ALL, so ?show_owned_only=true returned the WHOLE
// DEPLOYMENT instead of only owned secrets.
//
// RED before the fix: all three secrets, Total 3.
func TestListReadableSecrets_ShowOwnedOnlyStillWorksForAGlobalReader(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	owned, _ := seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20, ShowOwnedOnly: true})
	require.NoError(t, err)

	require.Equal(t, []string{owned}, listedNames(resp),
		"?show_owned_only=true must return only the owned secret; returning the whole deployment is the F2 defect. Got %v", listedNames(resp))
	assert.Equal(t, int64(1), resp.Total)
}

// TestListReadableSecrets_NoSharingFilterStillReturnsEverythingReadable is the
// calibration for both halves: with neither flag set, a global reader must still
// see every secret. Without it, a mutation that filtered to owned-only
// unconditionally would pass both tests above.
func TestListReadableSecrets_NoSharingFilterStillReturnsEverythingReadable(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(3), resp.Total,
		"a global reader with no sharing filter sees everything the grant authorizes; got %v", listedNames(resp))
}

// TestListReadableSecrets_AggregateSharingCountsArePopulatedForAGlobalReader is
// F3 (non-blocking in the review, but a live wire-field regression this PR
// introduced): owned_count / shared_count / acl_granted_count were populated
// only by ListSecretsWithSharingInfo, so after tier 1 moved off it they read 0
// for every global reader while the UI kept rendering them.
func TestListReadableSecrets_AggregateSharingCountsArePopulatedForAGlobalReader(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, 1, resp.OwnedCount, "one owned secret")
	assert.Equal(t, 1, resp.SharedCount, "one shared with them")
	// The third secret is role-visible only: not owned, not shared, no ACL — so it
	// is in Total and in none of the three buckets. Asserted so the counts are not
	// mistaken for a partition of Total.
	assert.Equal(t, 0, resp.ACLGrantedCount)
	assert.Equal(t, int64(3), resp.Total)
}

// TestListReadableSecrets_CountsDescribeTheWholeSetNotThePage pins that the
// aggregate counts follow Total's scope rather than the current page's — the
// mistake that would make them silently wrong for any reader past page 1.
func TestListReadableSecrets_CountsDescribeTheWholeSetNotThePage(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	seedOwnedAndSharedForReader(t, db)
	grantGlobalRead(t, db)

	resp, err := c.ListReadableSecrets(context.Background(), 1, 1,
		&models.SecretListFilter{Page: 1, PageSize: 1}) // one row per page
	require.NoError(t, err)
	require.Len(t, resp.Secrets, 1, "page size 1")
	assert.Equal(t, int64(3), resp.Total)
	// 2, not 1: owned=1 + shared=1 over the WHOLE set. A page-scoped
	// implementation would report at most 1 here, since the page holds one row.
	assert.Equal(t, 2, resp.OwnedCount+resp.SharedCount+resp.ACLGrantedCount,
		fmt.Sprintf("the counts must cover the whole filtered set (owned=1, shared=1, acl=0), not just this page: got %d/%d/%d",
			resp.OwnedCount, resp.SharedCount, resp.ACLGrantedCount))
}
