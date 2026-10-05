// read_path_cache_querycount_test.go — the read-path cache is a PERFORMANCE
// mechanism, so the number of statements each path issues is part of its
// contract, not an implementation detail. These tests pin it by counting real
// statements through a GORM callback, because the regression they exist to
// catch is invisible to every correctness test: a cold GetSecret that issues
// TWO queries instead of one is still perfectly correct.
//
// Found while moving the four call sites onto read_path_cache.go: routing the
// same-row sites through the shared probe() made a cold read pay a generation
// query it never used (the stamp comes from the load itself in that variant).
// cachedReadSameRow now skips the stamp read when there is no entry to
// validate; cachedRead cannot, because reading the stamp before the load IS
// its ordering rule.
package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// statementCounter counts SELECTs issued through one *gorm.DB between Reset
// calls.
type statementCounter struct {
	mu sync.Mutex
	n  int
}

func (c *statementCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n = 0
}

func (c *statementCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func countQueries(t *testing.T, ls *LocalStorage) *statementCounter {
	t.Helper()
	ctr := &statementCounter{}
	const cb = "guard6:count-queries"
	require.NoError(t, ls.db.Callback().Query().After("gorm:query").Register(cb, func(*gorm.DB) {
		ctr.mu.Lock()
		ctr.n++
		ctr.mu.Unlock()
	}))
	t.Cleanup(func() { _ = ls.db.Callback().Query().After("gorm:query").Remove(cb) })
	return ctr
}

func TestCachedReadSameRow_ColdReadIssuesOneQuery(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)

	ctr := countQueries(t, ls)

	// Cold: nothing cached, so there is no stamp to validate and the stamp
	// comes from the row itself — one query, exactly as before the cache.
	ctr.reset()
	_, err = ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, ctr.count(), "a cold same-row read must not pay for a generation query it cannot use")

	// Warm hit: the one cheap generation check, and no row fetch.
	ctr.reset()
	_, err = ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, ctr.count(), "a same-row cache hit is exactly one generation query")
}

func TestCachedRead_WarmHitIssuesOneQuery(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	created, err := ls.CreateSecret(ctx, &models.SecretNode{Name: "x", ProjectID: 1, EnvironmentID: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	require.NoError(t, err)
	_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: created.ID, VersionNumber: 1, CreatedAt: time.Now()})
	require.NoError(t, err)

	ctr := countQueries(t, ls)

	// Cold: the stamp read is MANDATORY here and must precede the load, so two
	// queries is the correct, intended cost — pinned so a "saving" that
	// reorders them cannot be made by accident.
	ctr.reset()
	_, err = ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 2, ctr.count(), "a cold cross-row read is the stamp read plus the load, in that order")

	ctr.reset()
	_, err = ls.GetLatestSecretVersion(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, 1, ctr.count(), "a cross-row cache hit is exactly one generation query")
}
