package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newUsageTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretAccessLog{}))
	return NewLocalStorage(db)
}

func seedUsageFixtures(t *testing.T, ls *LocalStorage, now time.Time) {
	t.Helper()
	ctx := context.Background()
	secrets := []*models.SecretNode{
		{ID: 1, Name: "hot-key", EnvironmentID: 1, IsSecret: true},
		{ID: 2, Name: "warm-key", EnvironmentID: 1, IsSecret: true},
		{ID: 3, Name: "never-read", EnvironmentID: 1, IsSecret: true},
		{ID: 4, Name: "stale-key", EnvironmentID: 1, IsSecret: true},
		{ID: 5, Name: "a-folder", EnvironmentID: 1, IsSecret: false},
	}
	for _, s := range secrets {
		require.NoError(t, ls.db.WithContext(ctx).Create(s).Error)
	}

	read := func(secretID uint, at time.Time, action string) {
		require.NoError(t, ls.db.WithContext(ctx).Create(&models.SecretAccessLog{
			SecretNodeID: secretID, AccessedBy: "u", AccessTime: at, Action: action,
		}).Error)
	}
	// hot-key: 3 recent reads. warm-key: 1 recent read.
	read(1, now.AddDate(0, 0, -1), "read")
	read(1, now.AddDate(0, 0, -2), "read")
	read(1, now.AddDate(0, 0, -3), "read")
	read(2, now.AddDate(0, 0, -5), "read")
	// stale-key: only an old read (60d ago).
	read(4, now.AddDate(0, 0, -60), "read")
	// folder gets a recent read (must be excluded from both reports).
	read(5, now.AddDate(0, 0, -1), "read")
	// a non-read action on hot-key must not inflate the read count.
	read(1, now.AddDate(0, 0, -1), "update")
}

// seedUsageFixturesEnv2 seeds a second, distinctly-identifiable environment
// (EnvironmentID 2) alongside seedUsageFixtures' environment 1, so tests can
// assert that an environment-scoped query returns only one environment's
// data and never leaks the other's.
func seedUsageFixturesEnv2(t *testing.T, ls *LocalStorage, now time.Time) {
	t.Helper()
	ctx := context.Background()
	secrets := []*models.SecretNode{
		{ID: 6, Name: "env2-hot-key", EnvironmentID: 2, IsSecret: true},
		{ID: 7, Name: "env2-never-read", EnvironmentID: 2, IsSecret: true},
	}
	for _, s := range secrets {
		require.NoError(t, ls.db.WithContext(ctx).Create(s).Error)
	}
	require.NoError(t, ls.db.WithContext(ctx).Create(&models.SecretAccessLog{
		SecretNodeID: 6, AccessedBy: "u", AccessTime: now.AddDate(0, 0, -1), Action: "read",
	}).Error)
}

func TestMostAccessedSecrets(t *testing.T) {
	ls := newUsageTestStore(t)
	now := time.Now()
	seedUsageFixtures(t, ls, now)

	stats, err := ls.MostAccessedSecrets(context.Background(), nil, nil, now.AddDate(0, 0, -30), 10)
	require.NoError(t, err)
	require.Len(t, stats, 2, "only secrets read within the window, folders excluded")

	assert.Equal(t, uint(1), stats[0].SecretID)
	assert.Equal(t, "hot-key", stats[0].SecretName)
	assert.Equal(t, int64(3), stats[0].ReadCount, "non-read actions are not counted")
	assert.Equal(t, uint(2), stats[1].SecretID)
	assert.Equal(t, int64(1), stats[1].ReadCount)
	require.NotNil(t, stats[0].LastRead)
}

func TestMostAccessedSecrets_RespectsLimit(t *testing.T) {
	ls := newUsageTestStore(t)
	now := time.Now()
	seedUsageFixtures(t, ls, now)

	stats, err := ls.MostAccessedSecrets(context.Background(), nil, nil, now.AddDate(0, 0, -30), 1)
	require.NoError(t, err)
	require.Len(t, stats, 1)
	assert.Equal(t, "hot-key", stats[0].SecretName)
}

// TestMostAccessedSecrets_ScopedToEnvironment is the regression test for the
// scope-widening leak: a caller authorized for (or intending to query) only
// one environment must not receive another environment's usage data mixed
// into the result, even though both environments live in the same project
// scope. Confirms the fix FAILS pre-fix (environmentID silently ignored,
// returning both environments' secrets) and PASSES post-fix.
func TestMostAccessedSecrets_ScopedToEnvironment(t *testing.T) {
	ls := newUsageTestStore(t)
	now := time.Now()
	seedUsageFixtures(t, ls, now)     // environment 1: hot-key (3 reads), warm-key (1 read), ...
	seedUsageFixturesEnv2(t, ls, now) // environment 2: env2-hot-key (1 read)

	env1 := uint(1)
	stats, err := ls.MostAccessedSecrets(context.Background(), nil, &env1, now.AddDate(0, 0, -30), 10)
	require.NoError(t, err)
	var names []string
	for _, s := range stats {
		names = append(names, s.SecretName)
	}
	assert.NotContains(t, names, "env2-hot-key", "environment 1 scoped query must not leak environment 2's usage data")
	assert.Contains(t, names, "hot-key")

	env2 := uint(2)
	stats2, err := ls.MostAccessedSecrets(context.Background(), nil, &env2, now.AddDate(0, 0, -30), 10)
	require.NoError(t, err)
	require.Len(t, stats2, 1, "environment 2 scoped query must return only environment 2's secret")
	assert.Equal(t, "env2-hot-key", stats2[0].SecretName)

	// No environment filter: preserves today's project-wide aggregate behavior.
	statsAll, err := ls.MostAccessedSecrets(context.Background(), nil, nil, now.AddDate(0, 0, -30), 10)
	require.NoError(t, err)
	var allNames []string
	for _, s := range statsAll {
		allNames = append(allNames, s.SecretName)
	}
	assert.Contains(t, allNames, "hot-key")
	assert.Contains(t, allNames, "env2-hot-key")
}

func TestUnusedSecrets(t *testing.T) {
	ls := newUsageTestStore(t)
	now := time.Now()
	seedUsageFixtures(t, ls, now)

	stats, err := ls.UnusedSecrets(context.Background(), nil, nil, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Len(t, stats, 2, "never-read + stale, excluding recently-read and folders")

	// Never-read is ordered first; its LastRead is nil.
	assert.Equal(t, "never-read", stats[0].SecretName)
	assert.Nil(t, stats[0].LastRead)
	assert.Equal(t, "stale-key", stats[1].SecretName)
	require.NotNil(t, stats[1].LastRead)
}

// TestUnusedSecrets_ScopedToEnvironment is the regression test for the
// scope-widening leak on the UnusedSecrets side: an environment-scoped query
// must not return another environment's never-read/stale secrets.
func TestUnusedSecrets_ScopedToEnvironment(t *testing.T) {
	ls := newUsageTestStore(t)
	now := time.Now()
	seedUsageFixtures(t, ls, now)     // environment 1: never-read, stale-key are unused
	seedUsageFixturesEnv2(t, ls, now) // environment 2: env2-never-read is unused

	env1 := uint(1)
	stats, err := ls.UnusedSecrets(context.Background(), nil, &env1, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	var names []string
	for _, s := range stats {
		names = append(names, s.SecretName)
	}
	assert.NotContains(t, names, "env2-never-read", "environment 1 scoped query must not leak environment 2's unused-secret data")
	assert.Contains(t, names, "never-read")

	env2 := uint(2)
	stats2, err := ls.UnusedSecrets(context.Background(), nil, &env2, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	require.Len(t, stats2, 1, "environment 2 scoped query must return only environment 2's unused secret")
	assert.Equal(t, "env2-never-read", stats2[0].SecretName)

	// No environment filter: preserves today's project-wide aggregate behavior.
	statsAll, err := ls.UnusedSecrets(context.Background(), nil, nil, now.AddDate(0, 0, -30))
	require.NoError(t, err)
	var allNames []string
	for _, s := range statsAll {
		allNames = append(allNames, s.SecretName)
	}
	assert.Contains(t, allNames, "never-read")
	assert.Contains(t, allNames, "env2-never-read")
}
