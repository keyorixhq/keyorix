package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Paginated list queries must have a deterministic order, so that walking the
// pages returns every row exactly once. Without ORDER BY the order follows the
// query plan, and PostgreSQL changes plan (index order -> heap order) once
// statistics exist; a walk that straddles that change repeats and skips rows.

type pageWalkEnv struct {
	ls      *LocalStorage
	analyze func(t *testing.T) // runs ANALYZE on PostgreSQL between pages; no-op elsewhere
}

func seedPageWalkRows(t *testing.T, ls *LocalStorage) (users, secrets, groups int) {
	t.Helper()
	names := []string{"a_b", "0", "a%b", `a\b`, "Zed", "zed2", "mid", "Mid2", "b", "B2", "c-1", "c_1"}
	for _, n := range names {
		require.NoError(t, ls.db.Create(&models.User{
			Username: n, UsernameFolded: strings.ToLower(n), Email: n + "@example.test", IsActive: true,
		}).Error)
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: n, IsSecret: true,
		}).Error)
		require.NoError(t, ls.db.Create(&models.Group{Name: n}).Error)
	}
	// Secrets with equal names in different environments exercise the tiebreak.
	for env := uint(2); env <= 4; env++ {
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: env, Name: "tie", IsSecret: true,
		}).Error)
	}
	return len(names), len(names) + 3, len(names)
}

func runPageWalkTests(t *testing.T, env pageWalkEnv) {
	ctx := context.Background()
	nUsers, nSecrets, nGroups := seedPageWalkRows(t, env.ls)

	t.Run("ListUsers", func(t *testing.T) {
		var seen []uint
		for page := 1; ; page++ {
			got, total, err := env.ls.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: 1})
			require.NoError(t, err)
			require.EqualValues(t, nUsers, total)
			if len(got) == 0 {
				break
			}
			for _, u := range got {
				seen = append(seen, u.ID)
			}
			if page == 1 {
				env.analyze(t)
			}
		}
		requireExactlyOnce(t, seen, nUsers)
	})

	t.Run("ListSecrets", func(t *testing.T) {
		var seen []uint
		for page := 1; ; page++ {
			got, total, err := env.ls.ListSecrets(ctx, &storage.SecretFilter{Page: page, PageSize: 1})
			require.NoError(t, err)
			require.EqualValues(t, nSecrets, total)
			if len(got) == 0 {
				break
			}
			for _, s := range got {
				seen = append(seen, s.ID)
			}
			if page == 1 {
				env.analyze(t)
			}
		}
		requireExactlyOnce(t, seen, nSecrets)
	})

	t.Run("ListGroupsPage", func(t *testing.T) {
		var seen []uint
		for off := 0; ; off++ {
			got, total, err := env.ls.ListGroupsPage(ctx, off, 1)
			require.NoError(t, err)
			require.EqualValues(t, nGroups, total)
			if len(got) == 0 {
				break
			}
			for _, g := range got {
				seen = append(seen, g.ID)
			}
			if off == 0 {
				env.analyze(t)
			}
		}
		requireExactlyOnce(t, seen, nGroups)
	})

	t.Run("ListUsers_page_walk_equals_one_big_page", func(t *testing.T) {
		all, _, err := env.ls.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1000})
		require.NoError(t, err)
		var want []uint
		for _, u := range all {
			want = append(want, u.ID)
		}
		require.True(t, sort.SliceIsSorted(want, func(i, j int) bool { return want[i] < want[j] }),
			"users must come back in id order")
		var got []uint
		for page := 1; page <= (nUsers+4)/5; page++ {
			part, _, err := env.ls.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: 5})
			require.NoError(t, err)
			for _, u := range part {
				got = append(got, u.ID)
			}
		}
		require.Equal(t, want, got)
	})
}

func requireExactlyOnce(t *testing.T, seen []uint, n int) {
	t.Helper()
	count := map[uint]int{}
	for _, id := range seen {
		count[id]++
	}
	for id, c := range count {
		require.Equal(t, 1, c, "row %d returned %d times", id, c)
	}
	require.Len(t, count, n, fmt.Sprintf("walk returned %d distinct rows, want %d (seen %v)", len(count), n, seen))
}

func TestListPagination_WalkReturnsEveryRowOnce_SQLite(t *testing.T) {
	ls := newFoldSQLiteStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.Group{}))
	runPageWalkTests(t, pageWalkEnv{ls: ls, analyze: func(*testing.T) {}})
}

// PostgreSQL leg: ANALYZE between page 1 and page 2 flips the plan of an
// unordered query from index order to heap order. With a deterministic ORDER BY
// the walk is unaffected. Skipped unless KEYORIX_TEST_PG_DSN is set.
func TestListPagination_WalkReturnsEveryRowOnce_Postgres(t *testing.T) {
	ls := newFoldPGStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.Group{}))
	// The production partial unique index (created by the storage factory, not by
	// AutoMigrate). On a fresh table the planner walks this index for an unordered
	// "SELECT ... FROM users", which is what makes the order change after ANALYZE.
	require.NoError(t, ls.db.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL").Error)
	runPageWalkTests(t, pageWalkEnv{ls: ls, analyze: func(t *testing.T) {
		for _, tbl := range []string{"users", "secret_nodes", "groups"} {
			require.NoError(t, ls.db.Exec("ANALYZE "+tbl).Error)
		}
	}})
}
