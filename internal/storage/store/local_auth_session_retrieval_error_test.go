// local_auth_session_retrieval_error_test.go covers item 3 of the UX-fixes batch: GetSession
// must distinguish a genuine "no such live session" from any other retrieval failure, so
// core.Logout (internal/core/auth.go) can tell a double-logout (ordinary 401) apart from a
// real storage fault (must not be silently reported as the same 401, #2337's own fix went too
// far by collapsing both into one sentinel). Red on main: a closed-connection failure was
// wrapped identically to a genuine not-found (both under "ErrorNotFound"), so
// storage.IsSessionNotFound(err) returned true for BOTH cases. Green after the fix: only the
// genuine not-found case satisfies it.
package store

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var sessionRetrievalErrorTestCounter atomic.Int64

// newSessionRetrievalErrorStore opens a uniquely-named in-memory SQLite DB with just the
// sessions table this test needs.
func newSessionRetrievalErrorStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	n := sessionRetrievalErrorTestCounter.Add(1)
	dsn := fmt.Sprintf("file:kxsessionretrieval_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	return NewLocalStorage(db), db
}

// newSessionRetrievalErrorPGStore is newSessionRetrievalErrorStore's PostgreSQL counterpart,
// isolated in its own dedicated schema (same pattern as local_audit_read_agg_test.go's
// newReadAggPGStore). Skips (not fails) when KEYORIX_TEST_PG_DSN is unset.
func newSessionRetrievalErrorPGStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	schema := "session_retrieval_error_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Session{}))
	return NewLocalStorage(db), db
}

// testGetSessionDistinguishesNotFoundFromRetrievalFailure is shared by the SQLite and
// Postgres variants below: a token that never existed is a genuine not-found
// (storage.IsSessionNotFound true); once the connection itself is closed, GetSession still
// errors, but for a completely different reason -- IsSessionNotFound must now be false, and
// the error text must not claim "not found" at all.
func testGetSessionDistinguishesNotFoundFromRetrievalFailure(t *testing.T, ls *LocalStorage, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()

	_, err := ls.GetSession(ctx, "never-existed-token")
	require.Error(t, err)
	assert.True(t, storage.IsSessionNotFound(err), "a token that never existed must be IsSessionNotFound: %v", err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = ls.GetSession(ctx, "never-existed-token")
	require.Error(t, err, "a closed connection must still produce an error")
	assert.False(t, storage.IsSessionNotFound(err),
		"a closed-connection retrieval failure must NOT be reported as session-not-found: %v", err)
}

func TestGetSession_DistinguishesNotFoundFromRetrievalFailure_SQLite(t *testing.T) {
	ls, db := newSessionRetrievalErrorStore(t)
	testGetSessionDistinguishesNotFoundFromRetrievalFailure(t, ls, db)
}

func TestGetSession_DistinguishesNotFoundFromRetrievalFailure_Postgres(t *testing.T) {
	ls, db := newSessionRetrievalErrorPGStore(t)
	testGetSessionDistinguishesNotFoundFromRetrievalFailure(t, ls, db)
}
