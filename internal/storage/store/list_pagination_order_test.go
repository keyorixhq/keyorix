package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
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
	// Extra secrets sharing the name "tie" across environments. The unfiltered
	// ListSecrets query has no name key, so these do not exercise a tiebreak; they
	// only add rows. The tiebreak cases are the equal-expiration and equal-deleted_at
	// subtests below.
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

	// Secrets sharing one expiration: ORDER BY expiration alone leaves the tie order to
	// the planner, and PostgreSQL's top-N heapsort under LIMIT/OFFSET orders tied rows
	// differently per page (a walk repeats one row and skips others). This is the
	// red-proven ListSecrets case: it fails at the base commit on PostgreSQL.
	t.Run("ListSecrets_ExpiresBefore_equal_expirations", func(t *testing.T) {
		const n = 40
		exp := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
		for i := range n {
			require.NoError(t, env.ls.db.Create(&models.SecretNode{
				ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("exp-tie-%02d", i), IsSecret: true,
				Expiration: &exp,
			}).Error)
		}
		env.analyze(t)
		before := exp.Add(time.Hour)
		for _, size := range []int{1, 3, 7} {
			var seen []uint
			for page := 1; ; page++ {
				got, total, err := env.ls.ListSecrets(ctx, &storage.SecretFilter{
					ExpiresBefore: &before, Page: page, PageSize: size,
				})
				require.NoError(t, err)
				require.EqualValues(t, n, total)
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
			requireExactlyOnce(t, seen, n)
		}
	})

	// Soft-deleted secrets sharing one deleted_at. Regression guard only: this was NOT
	// observed red at the base commit (the tie order happened to be stable there), and
	// the unfiltered ListSecrets and ListGroupsPage legs above are likewise defensive,
	// not red-proven.
	t.Run("ListSecrets_DeletedOnly_equal_deleted_at", func(t *testing.T) {
		const n = 40
		var ids []uint
		for i := range n {
			node := &models.SecretNode{
				ProjectID: 1, EnvironmentID: 1, Name: fmt.Sprintf("del-tie-%02d", i), IsSecret: true,
			}
			require.NoError(t, env.ls.db.Create(node).Error)
			ids = append(ids, node.ID)
		}
		deletedAt := time.Date(2030, 6, 7, 8, 9, 10, 0, time.UTC)
		require.NoError(t, env.ls.db.Unscoped().Model(&models.SecretNode{}).
			Where("id IN ?", ids).Update("deleted_at", deletedAt).Error)
		env.analyze(t)
		for _, size := range []int{1, 3, 7} {
			var seen []uint
			for page := 1; ; page++ {
				got, total, err := env.ls.ListSecrets(ctx, &storage.SecretFilter{
					DeletedOnly: true, Page: page, PageSize: size,
				})
				require.NoError(t, err)
				require.EqualValues(t, n, total)
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
			requireExactlyOnce(t, seen, n)
		}
	})
}

// newPagePGStore opens a PostgreSQL store in its own schema. It is separate from
// newFoldPGStore so the skip reason and the schema name belong to this test.
func newPagePGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL leg of the list pagination order test")
	}
	const schema = "list_pagination_order_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SecretNode{}))
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return NewLocalStorage(db)
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
	ls := newPagePGStore(t)
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
