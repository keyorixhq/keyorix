// session_i_users_search_sqlite_test.go — regression coverage for
// ListUsers(filter.Search != nil) against a REAL SQLite database (not a
// mock/stub storage). Every prior test of GET /api/v1/users/search
// (server/http/handlers/handlers_s24_test.go's TestSearchUsers_*) uses a
// mocked core service, which never executes the actual SQL this filter
// builds -- so the bug (ILIKE is Postgres-only syntax; SQLite's parser
// rejects it outright) was invisible to every existing test. Found live by
// SESSION-I's fresh-install API smoke driver (scripts/e2e) hitting
// GET /api/v1/users/search against a real, freshly migrated SQLite database.
package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestListUsers_Search_RealSQLite is the red/green regression: before the
// fix, this fails with a SQLite syntax error ("near "ILIKE": syntax error")
// because ListUsers unconditionally built an ILIKE clause regardless of
// dialect; after the fix, it returns the matching user via a dialect-
// appropriate (SQLite: plain LIKE, already ASCII-case-insensitive) query.
func TestListUsers_Search_RealSQLite(t *testing.T) {
	ctx := context.Background()
	ls := newUserStore(t)

	_, err := ls.CreateUser(ctx, &models.User{
		Username: "e2esmokeuser", Email: "e2esmokeuser@smoke.local", DisplayName: "E2E Smoke User",
	})
	require.NoError(t, err)
	_, err = ls.CreateUser(ctx, &models.User{
		Username: "unrelated", Email: "unrelated@example.com", DisplayName: "Unrelated Person",
	})
	require.NoError(t, err)

	search := "e2esmoke"
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{Search: &search, Page: 1, PageSize: 10})
	require.NoError(t, err, "ListUsers with a Search filter must not error on a real SQLite database")
	require.Equal(t, int64(1), total, "exactly one user should match the search term")
	require.Len(t, users, 1)
	require.Equal(t, "e2esmokeuser", users[0].Username)

	// Case-insensitivity must be preserved (the whole point of ILIKE on
	// Postgres, and the reason a naive plain-LIKE swap on EVERY dialect
	// would be a silent regression on Postgres, not just a fix on SQLite).
	upperSearch := "E2ESMOKE"
	users, total, err = ls.ListUsers(ctx, &storage.UserFilter{Search: &upperSearch, Page: 1, PageSize: 10})
	require.NoError(t, err)
	require.Equal(t, int64(1), total, "search must remain case-insensitive")
	require.Len(t, users, 1)
	require.Equal(t, "e2esmokeuser", users[0].Username)
}
