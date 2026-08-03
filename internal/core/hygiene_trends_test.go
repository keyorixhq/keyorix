package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedNow is the frozen clock used by all hygiene trend tests.
var hygieneFixedNow = time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

func newHygieneCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store, now: func() time.Time { return hygieneFixedNow }}
}

// setupComputeCalls sets up the five storage calls made by computeHygieneTrendPoint.
func setupComputeCalls(store *MockStorage, ctx context.Context, stalePATs, expiredPATs, staleMachines int, pats []*models.PersonalAccessToken, machines []*models.MachineIdentity) {
	store.On("CountStalePATs", ctx, mock.AnythingOfType("time.Time")).Return(stalePATs, nil)
	store.On("CountExpiredPATs", ctx).Return(expiredPATs, nil)
	store.On("CountStaleMachineCredentials", ctx, mock.AnythingOfType("time.Time")).Return(staleMachines, nil)
	store.On("ListActivePersonalAccessTokens", ctx).Return(pats, nil)
	store.On("ListAllMachineIdentities", ctx).Return(machines, nil)
}

// --- GetHygieneTrends ---

func TestGetHygieneTrends_ValidDaysAccepted(t *testing.T) {
	for _, days := range []int{30, 60, 90} {
		store := new(MockStorage)
		c := newHygieneCore(store)
		ctx := context.Background()

		setupComputeCalls(store, ctx, 1, 2, 3,
			[]*models.PersonalAccessToken{{}, {}},
			[]*models.MachineIdentity{{State: "active"}, {State: "revoked"}},
		)
		store.On("ListHygieneTrendSnapshots", ctx, days).Return([]*models.HygieneTrendSnapshot{}, nil)

		report, err := c.GetHygieneTrends(ctx, days)
		require.NoError(t, err)
		assert.Equal(t, days, report.Days)
	}
}

func TestGetHygieneTrends_InvalidDaysDefaultsTo30(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	setupComputeCalls(store, ctx, 0, 0, 0,
		[]*models.PersonalAccessToken{},
		[]*models.MachineIdentity{},
	)
	store.On("ListHygieneTrendSnapshots", ctx, 30).Return([]*models.HygieneTrendSnapshot{}, nil)

	report, err := c.GetHygieneTrends(ctx, 15) // invalid
	require.NoError(t, err)
	assert.Equal(t, 30, report.Days)
	store.AssertCalled(t, "ListHygieneTrendSnapshots", ctx, 30)
}

func TestGetHygieneTrends_TodayPointPopulatedFromLiveState(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	setupComputeCalls(store, ctx, 5, 3, 2,
		[]*models.PersonalAccessToken{{}, {}, {}},                                           // 3 PATs
		[]*models.MachineIdentity{{State: "active"}, {State: "active"}, {State: "revoked"}}, // 2 active
	)
	store.On("ListHygieneTrendSnapshots", ctx, 30).Return([]*models.HygieneTrendSnapshot{}, nil)

	report, err := c.GetHygieneTrends(ctx, 30)
	require.NoError(t, err)
	require.Len(t, report.Points, 1)
	today := report.Points[0]
	assert.Equal(t, 5, today.StalePATs)
	assert.Equal(t, 3, today.ExpiredPATs)
	assert.Equal(t, 2, today.StaleMachines)
	assert.Equal(t, 3, today.TotalPATs)
	assert.Equal(t, 2, today.TotalMachines)
}

func TestGetHygieneTrends_HistoricalPointsAppended(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	yesterday := hygieneFixedNow.UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	dayBefore := hygieneFixedNow.UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour)

	setupComputeCalls(store, ctx, 0, 0, 0,
		[]*models.PersonalAccessToken{},
		[]*models.MachineIdentity{},
	)
	store.On("ListHygieneTrendSnapshots", ctx, 30).Return([]*models.HygieneTrendSnapshot{
		{SnapshotDate: yesterday, StalePATs: 10, ExpiredPATs: 4, StaleMachines: 1, TotalPATs: 20, TotalMachines: 5},
		{SnapshotDate: dayBefore, StalePATs: 8, ExpiredPATs: 2, StaleMachines: 0, TotalPATs: 18, TotalMachines: 5},
	}, nil)

	report, err := c.GetHygieneTrends(ctx, 30)
	require.NoError(t, err)
	require.Len(t, report.Points, 3) // today + 2 historical
	assert.Equal(t, 10, report.Points[1].StalePATs)
	assert.Equal(t, 8, report.Points[2].StalePATs)
}

func TestGetHygieneTrends_TodaySnapshotExcluded(t *testing.T) {
	// A stored snapshot whose SnapshotDate equals today must be dropped — the
	// live computation already provides today's point.
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	todayMidnight := truncateToDay(hygieneFixedNow)
	yesterday := todayMidnight.AddDate(0, 0, -1)

	setupComputeCalls(store, ctx, 0, 0, 0,
		[]*models.PersonalAccessToken{},
		[]*models.MachineIdentity{},
	)
	store.On("ListHygieneTrendSnapshots", ctx, 30).Return([]*models.HygieneTrendSnapshot{
		{SnapshotDate: todayMidnight, StalePATs: 99}, // stale snapshot for today — must be skipped
		{SnapshotDate: yesterday, StalePATs: 7},
	}, nil)

	report, err := c.GetHygieneTrends(ctx, 30)
	require.NoError(t, err)
	require.Len(t, report.Points, 2)               // today (live) + yesterday only
	assert.Equal(t, 0, report.Points[0].StalePATs) // live value, not 99
	assert.Equal(t, 7, report.Points[1].StalePATs)
}

func TestGetHygieneTrends_CountStalePATsError(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	store.On("CountStalePATs", ctx, mock.AnythingOfType("time.Time")).
		Return(0, errors.New("db error"))

	_, err := c.GetHygieneTrends(ctx, 30)
	require.Error(t, err)
}

func TestGetHygieneTrends_ListSnapshotsError(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	setupComputeCalls(store, ctx, 0, 0, 0,
		[]*models.PersonalAccessToken{},
		[]*models.MachineIdentity{},
	)
	store.On("ListHygieneTrendSnapshots", ctx, 30).Return(nil, errors.New("db error"))

	_, err := c.GetHygieneTrends(ctx, 30)
	require.Error(t, err)
}

// --- RecordHygieneTrendPoint ---

func TestRecordHygieneTrendPoint_PersistsSnapshot(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	setupComputeCalls(store, ctx, 4, 1, 2,
		[]*models.PersonalAccessToken{{}, {}, {}, {}},
		[]*models.MachineIdentity{{State: "active"}, {State: "active"}, {State: "suspended"}},
	)
	store.On("SaveHygieneTrendSnapshot", ctx, mock.AnythingOfType("*models.HygieneTrendSnapshot")).Return(nil)

	point, err := c.RecordHygieneTrendPoint(ctx)
	require.NoError(t, err)
	assert.Equal(t, 4, point.StalePATs)
	assert.Equal(t, 1, point.ExpiredPATs)
	assert.Equal(t, 2, point.StaleMachines)
	assert.Equal(t, 4, point.TotalPATs)
	assert.Equal(t, 2, point.TotalMachines)

	store.AssertCalled(t, "SaveHygieneTrendSnapshot", ctx,
		mock.MatchedBy(func(s *models.HygieneTrendSnapshot) bool {
			return s.StalePATs == 4 &&
				s.ExpiredPATs == 1 &&
				s.StaleMachines == 2 &&
				s.TotalPATs == 4 &&
				s.TotalMachines == 2 &&
				s.SnapshotDate.Equal(truncateToDay(hygieneFixedNow))
		}),
	)
}

func TestRecordHygieneTrendPoint_PropagatesSaveError(t *testing.T) {
	store := new(MockStorage)
	c := newHygieneCore(store)
	ctx := context.Background()

	setupComputeCalls(store, ctx, 0, 0, 0,
		[]*models.PersonalAccessToken{},
		[]*models.MachineIdentity{},
	)
	store.On("SaveHygieneTrendSnapshot", ctx, mock.AnythingOfType("*models.HygieneTrendSnapshot")).
		Return(errors.New("write failed"))

	_, err := c.RecordHygieneTrendPoint(ctx)
	require.Error(t, err)
}

func TestTruncateToDay_ReturnsUTCMidnight(t *testing.T) {
	ts := time.Date(2026, 3, 15, 17, 45, 59, 999, time.UTC)
	got := truncateToDay(ts)
	assert.Equal(t, time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), got)
}
