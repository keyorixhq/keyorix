package core

// share_list_cap_siblings_test.go — REVIEW-3018, the two siblings
// TestShareListFetchCallersRefuseAtTheCap listed OPEN: the shared-with-me secret
// listing (getSharedSecretsWithSharingInfo) truncated silently at the storage cap,
// and GetDashboardStats showed a floor as the shared_secrets / shared_with_me count.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSharedWithMeSecretListing_RefusesAFetchAtTheCap(t *testing.T) {
	t.Parallel()
	c, _, _ := mustShare(t)
	c.storage = fixedShareLists(c.storage, shareRecords(1, maxShareViewBatchSize), nil)

	resp, err := c.ListSecretsWithSharingInfo(context.Background(), 2, &models.SecretListFilter{ShowSharedOnly: true})
	require.ErrorIs(t, err, ErrShareListOverCap,
		"a received-share fetch at the storage cap may be truncated; the shared-with-me listing must be refused, not returned short")
	assert.Nil(t, resp)
}

// Positive control: one row under the cap is listed, so the refusal above cannot
// pass by refusing everything.
func TestSharedWithMeSecretListing_ListsAFetchUnderTheCap(t *testing.T) {
	t.Parallel()
	c, secretID, _ := mustShare(t)
	under := shareRecords(1, maxShareViewBatchSize-1)
	for _, s := range under {
		s.SecretID = secretID
	}
	c.storage = fixedShareLists(c.storage, under, nil)

	resp, err := c.ListSecretsWithSharingInfo(context.Background(), 2, &models.SecretListFilter{ShowSharedOnly: true})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Secrets, "the shared secret is listed")
}

func sharedDegradeReasons(stats *DashboardStats) []string {
	var out []string
	for _, r := range stats.DegradedReasons {
		if strings.HasPrefix(r, "shared_") {
			out = append(out, r)
		}
	}
	return out
}

func TestGetDashboardStats_DegradesShareCountsAtTheCap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		received, owned []*models.ShareRecord
		want            string
	}{
		{"outgoing at the cap", nil, shareRecords(1, maxShareViewBatchSize), "shared_secrets"},
		{"incoming at the cap", shareRecords(1, maxShareViewBatchSize), nil, "shared_with_me"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _, _ := mustShare(t)
			c.storage = fixedShareLists(c.storage, tc.received, tc.owned)

			stats, err := c.GetDashboardStats(context.Background(), 1, "", 1)
			require.NoError(t, err)
			assert.True(t, stats.Degraded, "a share count from a fetch at the cap is a floor: the snapshot must say so")
			reasons := sharedDegradeReasons(stats)
			require.Len(t, reasons, 1, "only the fetch at the cap degrades its tile: %v", stats.DegradedReasons)
			assert.True(t, strings.HasPrefix(reasons[0], tc.want+":"), "degraded tile: %v", reasons)
		})
	}
}

// Positive control: fetches under the cap are counted and degrade nothing.
func TestGetDashboardStats_CountsShareFetchesUnderTheCap(t *testing.T) {
	t.Parallel()
	c, _, _ := mustShare(t)
	under := maxShareViewBatchSize - 1
	c.storage = fixedShareLists(c.storage, shareRecords(1, under), shareRecords(1+under, under))

	stats, err := c.GetDashboardStats(context.Background(), 1, "", 1)
	require.NoError(t, err)
	assert.Empty(t, sharedDegradeReasons(stats), "fetches under the cap are counts, not floors")
	assert.Equal(t, under, stats.SharedSecrets)
	assert.Equal(t, under, stats.SecretsSharedWithMe)
}
