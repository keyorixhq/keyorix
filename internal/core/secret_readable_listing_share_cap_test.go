package core

// secret_readable_listing_share_cap_test.go — a received-share fetch at the storage
// cap, on every ListReadableSecrets tier.
//
// REVIEW-3974-DEEP-2 F1: tier 2 used to treat the refusal as one unreadable scope and
// skip it, and since it hits every non-empty scope alike, a project-role reader got a
// silently empty list (HTTP 200). #3943 then narrowed where the refusal applies: on
// tiers 1 and 2 the received shares only decorate rows the role already makes visible,
// so a fetch at the cap no longer refuses the list (that let a mass sharer deny the
// victim's listing); the rows are complete and only the decoration is partial. Tier 3
// (no role) lists exactly owned ∪ shared ∪ ACL, so there the shares ARE the rows and
// the refusal stays.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// readableListingTiers is every ListReadableSecrets tier, each with the grant that
// selects it. Project 1 holds three readable secrets in every case.
var readableListingTiers = []struct {
	name  string
	grant func(t *testing.T, db *gorm.DB)
}{
	{"tier1-global-reader", func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	}},
	{"tier2-project-role", func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	}},
	{"tier3-no-role", func(*testing.T, *gorm.DB) {}},
}

func shareCapTierFixture(t *testing.T, received []*models.ShareRecord, grant func(*testing.T, *gorm.DB)) *KeyorixCore {
	t.Helper()
	c, db := readableListingFixture(t)
	seedReadableProject(t, db, 1, "alpha", "a", 3)
	// seedReadableProject grants project 1; each tier sets its own grant instead.
	require.NoError(t, db.Where("user_id = ?", 1).Delete(&models.UserRole{}).Error)
	grant(t, db)
	c.storage = fixedShareLists(c.storage, received, nil)
	return c
}

func TestListReadableSecrets_ShareFetchAtTheCap(t *testing.T) {
	t.Parallel()
	for _, tier := range readableListingTiers {
		t.Run(tier.name, func(t *testing.T) {
			t.Parallel()
			c := shareCapTierFixture(t, shareRecords(1, maxShareViewBatchSize), tier.grant)
			ctx := context.Background()
			refuses := tier.name == "tier3-no-role"

			resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{})
			_, exact, cerr := c.CountReadableSecrets(ctx, 1, 1)
			if refuses {
				require.ErrorIs(t, err, ErrShareListOverCap,
					"tier 3's rows ARE the shares: a fetch at the cap must be refused, not answered as a shortened list")
				assert.Nil(t, resp)
				require.ErrorIs(t, cerr, ErrShareListOverCap, "the dashboard count goes through the same listing")
			} else {
				require.NoError(t, err, "the shares only decorate role-visible rows: the list must still answer (#3943)")
				assert.Equal(t, int64(3), resp.Total, "the role makes project 1's three secrets visible")
				require.NoError(t, cerr)
				assert.True(t, exact, "the count is the role-visible rows, not the share fetch")
			}

			stats, err := c.GetDashboardStats(ctx, 1, "reader", 1)
			require.NoError(t, err, "the dashboard degrades a tile, it does not fail")
			assert.True(t, stats.Degraded, "shared_with_me comes from a fetch at the cap: a floor, not a count")
			var totalDegraded bool
			for _, r := range stats.DegradedReasons {
				totalDegraded = totalDegraded || strings.HasPrefix(r, "total_secrets:")
			}
			assert.Equal(t, refuses, totalDegraded, "TOTAL SECRETS is degraded exactly where the listing refuses: %v", stats.DegradedReasons)
		})
	}
}

// Positive control: one share under the cap, and tiers 1 and 2 list project 1's
// secrets, so the refusal above cannot pass by refusing everything.
func TestListReadableSecrets_EveryTierListsAShareFetchUnderTheCap(t *testing.T) {
	t.Parallel()
	for _, tier := range readableListingTiers {
		t.Run(tier.name, func(t *testing.T) {
			t.Parallel()
			c := shareCapTierFixture(t, shareRecords(1, maxShareViewBatchSize-1), tier.grant)

			resp, err := c.ListReadableSecrets(context.Background(), 1, 1, &models.SecretListFilter{})
			require.NoError(t, err)
			if tier.name != "tier3-no-role" {
				assert.Equal(t, int64(3), resp.Total, "the role makes project 1's three secrets visible")
			}
		})
	}
}
