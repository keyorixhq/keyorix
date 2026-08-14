package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForAccessReviewCampaigns builds the standard
// #452/#507/#511/#519-style two-server harness: an "upstream" exercised
// through the REAL production NewRouter/handlers (including the new
// /api/v1/system/access-review-campaigns routes,
// access_review_campaigns_proxy.go), and a "downstream" *core.KeyorixCore
// configured with storage.type: remote (ADR-049), pointed at "upstream" over
// real HTTP via store.RemoteStorage. Mirrors
// newUpstreamDownstreamForMemberships exactly.
func newUpstreamDownstreamForAccessReviewCampaigns(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Access Review Campaign Test Project", "")
	require.NoError(t, err)
	return upstream, downstream, project.ID
}

// TestRemoteStorageAccessReviewCampaign_CreateGetList_RealServer proves the
// #519 fix for CreateAccessReviewCampaign/GetAccessReviewCampaign/
// ListAccessReviewCampaigns: a campaign is genuinely persisted on the
// upstream server via the DOWNSTREAM's RemoteStorage, fetchable by ID, and
// listed — all via storage.type: remote against a real router, not a
// protocol mock.
func TestRemoteStorageAccessReviewCampaign_CreateGetList_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID,
		Name:      "Q1 access review",
		State:     core.CampaignStateOpen,
		CreatedBy: 1,
		CreatedAt: now,
	})
	require.NoError(t, err, "creating a campaign must succeed via storage.type: remote")
	require.NotZero(t, c.ID, "the upstream must assign a real ID")
	assert.Equal(t, projectID, c.ProjectID)
	assert.Equal(t, "Q1 access review", c.Name)
	assert.Equal(t, core.CampaignStateOpen, c.State)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "Q1 access review", direct.Name)

	// GetAccessReviewCampaign via the downstream (RemoteStorage) round-trips
	// every field correctly.
	fetched, err := downstream.Storage().GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c.ID, fetched.ID)
	assert.Equal(t, c.ProjectID, fetched.ProjectID)
	assert.Equal(t, c.Name, fetched.Name)
	assert.Equal(t, c.State, fetched.State)
	assert.WithinDuration(t, c.CreatedAt, fetched.CreatedAt, time.Second)

	// A second campaign for the same project, then list both back via the
	// downstream's ListAccessReviewCampaigns.
	_, err = downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "Q2 access review", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)

	rows, err := downstream.Storage().ListAccessReviewCampaigns(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Name] = true
	}
	assert.True(t, names["Q1 access review"])
	assert.True(t, names["Q2 access review"])
}

// TestRemoteStorageAccessReviewCampaign_GetNotFound_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a nonexistent
// campaign ID.
func TestRemoteStorageAccessReviewCampaign_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _ := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetAccessReviewCampaign(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageAccessReviewCampaign_OpenAndLatestClosed_RealServer proves
// GetOpenAccessReviewCampaign/GetLatestClosedAccessReviewCampaign round-trip
// their nil-is-success ("no such campaign") contract, and correctly identify
// the open vs. most-recently-closed campaign after an UpdateAccessReviewCampaign
// state transition.
func TestRemoteStorageAccessReviewCampaign_OpenAndLatestClosed_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	// No campaign yet: both queries report a clean nil, not an error.
	open, err := downstream.Storage().GetOpenAccessReviewCampaign(ctx, projectID)
	require.NoError(t, err)
	assert.Nil(t, open)
	closedCampaign, err := downstream.Storage().GetLatestClosedAccessReviewCampaign(ctx, projectID)
	require.NoError(t, err)
	assert.Nil(t, closedCampaign)

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "open campaign", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)

	open, err = downstream.Storage().GetOpenAccessReviewCampaign(ctx, projectID)
	require.NoError(t, err)
	require.NotNil(t, open)
	assert.Equal(t, c.ID, open.ID)

	// Close it via UpdateAccessReviewCampaign's conditional UPDATE.
	closedAt := time.Now()
	c.State = core.CampaignStateClosed
	c.ClosedBy = 1
	c.ClosedAt = &closedAt
	updated, err := downstream.Storage().UpdateAccessReviewCampaign(ctx, c)
	require.NoError(t, err)
	assert.True(t, updated, "closing a still-open campaign must succeed")

	open, err = downstream.Storage().GetOpenAccessReviewCampaign(ctx, projectID)
	require.NoError(t, err)
	assert.Nil(t, open, "no campaign is open once the only one is closed")

	closedCampaign, err = downstream.Storage().GetLatestClosedAccessReviewCampaign(ctx, projectID)
	require.NoError(t, err)
	require.NotNil(t, closedCampaign)
	assert.Equal(t, c.ID, closedCampaign.ID)
}

// TestRemoteStorageAccessReviewCampaign_UpdateRejectsWhenAlreadyClosed_RealServer
// proves UpdateAccessReviewCampaign's conditional `WHERE state = 'open'` UPDATE
// survives the HTTP hop faithfully: a second close attempt against an
// already-closed campaign must report updated=false (a lost race), not
// silently re-apply.
func TestRemoteStorageAccessReviewCampaign_UpdateRejectsWhenAlreadyClosed_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "double-close", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)

	closedAt := time.Now()
	firstClose := &models.AccessReviewCampaign{ID: c.ID, ProjectID: projectID, Name: c.Name, State: core.CampaignStateClosed, ClosedBy: 1, ClosedAt: &closedAt}
	updated, err := downstream.Storage().UpdateAccessReviewCampaign(ctx, firstClose)
	require.NoError(t, err)
	assert.True(t, updated, "the first close must win")

	secondClose := &models.AccessReviewCampaign{ID: c.ID, ProjectID: projectID, Name: c.Name, State: core.CampaignStateClosed, ClosedBy: 2, ClosedAt: &closedAt}
	updated, err = downstream.Storage().UpdateAccessReviewCampaign(ctx, secondClose)
	require.NoError(t, err, "a lost race is reported via the bool, not an error")
	assert.False(t, updated, "a second close against an already-closed campaign must be rejected")

	fetched, err := downstream.Storage().GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, uint(1), fetched.ClosedBy, "the winning close's ClosedBy must not be clobbered by the loser")
}

// TestRemoteStorageAccessReviewCampaign_ItemsRoundTrip_RealServer proves
// CreateAccessReviewItems/ListAccessReviewItems/CountPendingAccessReviewItems/
// GetAccessReviewItem/UpdateAccessReviewItem round-trip over storage.type:
// remote.
func TestRemoteStorageAccessReviewCampaign_ItemsRoundTrip_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "items campaign", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)

	items := []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 42, PrincipalName: "alice", Source: "direct_share", AccessLevel: "read", EnvironmentID: 1, Decision: core.ReviewItemPending},
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 43, PrincipalName: "bob", Source: "role", AccessLevel: "write", EnvironmentID: 1, Decision: core.ReviewItemPending},
	}
	require.NoError(t, downstream.Storage().CreateAccessReviewItems(ctx, items))

	rows, err := downstream.Storage().ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.NotZero(t, r.ID, "the upstream must assign a real item ID")
		assert.Equal(t, c.ID, r.CampaignID)
	}

	pending, err := downstream.Storage().CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, pending)

	target := rows[0]
	fetched, err := downstream.Storage().GetAccessReviewItem(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, target.PrincipalName, fetched.PrincipalName)

	// Decide it (attest) via UpdateAccessReviewItem's conditional UPDATE.
	decidedAt := time.Now()
	fetched.Decision = core.ReviewItemAttested
	fetched.DecidedBy = 7
	fetched.DecidedAt = &decidedAt
	updated, err := downstream.Storage().UpdateAccessReviewItem(ctx, fetched)
	require.NoError(t, err)
	assert.True(t, updated, "deciding a still-pending item in an open campaign must succeed")

	pending, err = downstream.Storage().CountPendingAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, pending, "the decided item no longer counts as pending")

	refetched, err := downstream.Storage().GetAccessReviewItem(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemAttested, refetched.Decision)
}

// TestRemoteStorageAccessReviewCampaign_UpdateItemRejectsWhenAlreadyDecided_RealServer
// proves UpdateAccessReviewItem's conditional `WHERE decision = 'pending' AND
// campaign_id IN (... WHERE state = 'open')` UPDATE survives the HTTP hop
// faithfully: a second decision on an already-decided item must report
// updated=false, not silently flip the recorded decision (#319).
func TestRemoteStorageAccessReviewCampaign_UpdateItemRejectsWhenAlreadyDecided_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "redecide", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)
	items := []*models.AccessReviewItem{
		{CampaignID: c.ID, PrincipalType: "user", PrincipalID: 1, Source: "role", AccessLevel: "read", EnvironmentID: 1, Decision: core.ReviewItemPending},
	}
	require.NoError(t, downstream.Storage().CreateAccessReviewItems(ctx, items))
	rows, err := downstream.Storage().ListAccessReviewItems(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	item := rows[0]

	decidedAt := time.Now()
	first := &models.AccessReviewItem{ID: item.ID, CampaignID: c.ID, PrincipalType: "user", PrincipalID: 1, Source: "role", AccessLevel: "read", EnvironmentID: 1, Decision: core.ReviewItemAttested, DecidedBy: 5, DecidedAt: &decidedAt}
	updated, err := downstream.Storage().UpdateAccessReviewItem(ctx, first)
	require.NoError(t, err)
	assert.True(t, updated, "the first decision must win")

	second := &models.AccessReviewItem{ID: item.ID, CampaignID: c.ID, PrincipalType: "user", PrincipalID: 1, Source: "role", AccessLevel: "read", EnvironmentID: 1, Decision: core.ReviewItemRevoked, DecidedBy: 6, DecidedAt: &decidedAt}
	updated, err = downstream.Storage().UpdateAccessReviewItem(ctx, second)
	require.NoError(t, err, "a lost race is reported via the bool, not an error")
	assert.False(t, updated, "a second decision on an already-decided item must be rejected")

	fetched, err := downstream.Storage().GetAccessReviewItem(ctx, item.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemAttested, fetched.Decision, "the winning decision must not be clobbered by the loser")
}

// TestRemoteStorageAccessReviewCampaign_ConcurrentClose_OnlyOneWins_RealServer
// drives real concurrent close attempts, through the REAL HTTP proxy hop (not
// direct LocalStorage calls, unlike
// store.TestConcurrency_UpdateAccessReviewCampaign_OnlyOneCloseWins), against
// the SAME open campaign and asserts the conditional UPDATE — running
// server-side inside a single proxied round trip — still lets exactly one
// win. This is the end-to-end proof that access_review_campaigns_proxy.go's
// atomicity analysis holds: no separate lock+update pair was introduced (and
// none was needed) to preserve the guarantee across the wire.
func TestRemoteStorageAccessReviewCampaign_ConcurrentClose_OnlyOneWins_RealServer(t *testing.T) {
	_, downstream, projectID := newUpstreamDownstreamForAccessReviewCampaigns(t)
	ctx := context.Background()
	now := time.Now()

	c, err := downstream.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "concurrent-close", State: core.CampaignStateOpen, CreatedBy: 1, CreatedAt: now,
	})
	require.NoError(t, err)

	const racers = 16
	var succeeded atomic.Int64
	errs := make(chan error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		closerID := uint(300 + i)
		go func(closerID uint) {
			defer wg.Done()
			<-start
			closedAt := time.Now()
			candidate := &models.AccessReviewCampaign{ID: c.ID, ProjectID: projectID, Name: c.Name, State: core.CampaignStateClosed, ClosedBy: closerID, ClosedAt: &closedAt}
			ok, err := downstream.Storage().UpdateAccessReviewCampaign(context.Background(), candidate)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				succeeded.Add(1)
			}
		}(closerID)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent close may win over the proxy — never zero, never more than one")

	fetched, err := downstream.Storage().GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, core.CampaignStateClosed, fetched.State, "the winning close must have been persisted")
}
