// inactive_since_semantics_test.go — #3740: UserFilter.InactiveSince judges a user
// by COALESCE(last_login_at, created_at), so a user created a minute ago who has
// not logged in yet is not "inactive". Runs on SQLite always and on PostgreSQL when
// KEYORIX_TEST_PG_DSN is set. The sweep query (ListInactiveUsers) must agree.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestInactiveSinceSemantics(t *testing.T) {
	dialects := map[string]func(*testing.T) *LocalStorage{
		"sqlite": newUserTestStore,
		"postgres": func(t *testing.T) *LocalStorage {
			ls, _ := pipelinePGStore(t)
			require.NoError(t, ls.db.AutoMigrate(&models.User{}))
			return ls
		},
	}
	for name, open := range dialects {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			ls := open(t)
			now := time.Now().UTC()

			mk := func(username string, created time.Time, lastLogin *time.Time) {
				t.Helper()
				u, err := ls.CreateUser(ctx, &models.User{Username: username, UsernameFolded: username, Email: username + "@x.io", EmailFolded: username + "@x.io"})
				require.NoError(t, err)
				require.NoError(t, ls.db.Model(&models.User{}).Where("id = ?", u.ID).UpdateColumn("created_at", created).Error)
				if lastLogin != nil {
					require.NoError(t, ls.UpdateLastLogin(ctx, u.ID, *lastLogin))
				}
			}
			ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
			const day = 24 * time.Hour

			mk("new_never", now.Add(-time.Minute), nil)      // created a minute ago, never logged in: NOT inactive
			mk("old_never", now.Add(-40*day), nil)           // created 40d ago, never logged in: inactive
			mk("stale", now.Add(-90*day), ago(40*day))       // last login 40d ago: inactive
			mk("fresh", now.Add(-90*day), ago(day))          // last login yesterday: NOT inactive
			mk("new_then_login", now.Add(-50*day), ago(day)) // old account, recent login: NOT inactive

			cutoff := now.Add(-30 * day)
			want := map[string]bool{"old_never": true, "stale": true}

			users, total, err := ls.ListUsers(ctx, &storage.UserFilter{InactiveSince: &cutoff, Page: 1, PageSize: 20})
			require.NoError(t, err)
			got := map[string]bool{}
			for _, u := range users {
				got[u.Username] = true
			}
			require.Equal(t, want, got, "ListUsers(InactiveSince)")
			require.EqualValues(t, len(want), total)

			// The suspend sweep's query must classify the same way.
			swept, err := ls.ListInactiveUsers(ctx, cutoff)
			require.NoError(t, err)
			gotSweep := map[string]bool{}
			for _, u := range swept {
				gotSweep[u.Username] = true
			}
			require.Equal(t, want, gotSweep, "ListInactiveUsers")
		})
	}
}
