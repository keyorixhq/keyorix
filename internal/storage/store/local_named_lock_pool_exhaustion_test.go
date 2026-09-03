// local_named_lock_pool_exhaustion_test.go — Part 2 regression audit finding
// (adversarial review run 2): a nested WithNamedLock call under a DIFFERENT
// key used to require a SECOND simultaneous pooled connection on the
// Postgres path (one per lock key), because PostgreSQL advisory locks are
// session-scoped and each WithNamedLock call pulled its own connection via
// sqlDB.Conn(ctx). Under a constrained connection pool, the outer call holds
// the pool's only connection for the entire duration of fn -- which is
// itself the blocked inner call waiting for a connection only the outer call
// could release. An indefinite deadlock, not contention, verified against
// real Postgres with MaxOpenConns(1). Fixed by reusing the outer call's
// connection for every nested key in the same call chain (see
// namedLockConnCtxKey in local_named_lock.go) -- Postgres advisory locks let
// one connection hold any number of distinct-key locks simultaneously, so a
// call chain nesting N distinct keys still needs only ONE pooled connection.
//
// Gated behind KEYORIX_TEST_PG_DSN like every other real-Postgres test in
// this package (see postgres_contention_helpers_test.go) -- a single SQLite
// connection can't reproduce a connection-pool deadlock at all.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithNamedLock_NestedDifferentKey_DoesNotExhaustConnectionPool(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	db := pgOpen(t, dsn)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	ls := NewLocalStorage(db)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	start := time.Now()
	err = ls.WithNamedLock(ctx, "pool-exhaustion-outer", func(ctx context.Context) error {
		return ls.WithNamedLock(ctx, "pool-exhaustion-inner", func(ctx context.Context) error {
			return nil
		})
	})
	elapsed := time.Since(start)

	require.NoError(t, err, "nested WithNamedLock under a different key must succeed, not deadlock waiting for a second pooled connection (took %s)", elapsed)
	require.Less(t, elapsed, 2*time.Second, "must complete quickly, not hang until the context deadline")
}
