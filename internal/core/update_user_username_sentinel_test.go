package core

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTHZ-ORACLE-TAILS-1 item 1: UpdateUser and UpdateUserIfActiveStateMatches map a
// collision on the users username index to storage.ErrDuplicateUsername (and one on
// the email index to storage.ErrDuplicateEmail), never one for the other, exactly as
// CreateUser does (TestLocalStorage_UserUniqueViolationsAreTyped). Production schema,
// SQLite and Postgres.

func seedRenameUser(t *testing.T, w *txClosureWorld, name string) *models.User {
	t.Helper()
	u := &models.User{
		Username: name, UsernameFolded: name, Email: name + "@example.com", EmailFolded: name + "@example.com",
		IsActive: true, AccountState: AccountActive,
	}
	require.NoError(t, w.db.Create(u).Error)
	return u
}

// updatePaths are the user-update storage entry points that can collide on a unique index.
var updatePaths = []struct {
	name  string
	write func(ctx context.Context, w *txClosureWorld, u *models.User) error
}{
	{"UpdateUserIfActiveStateMatches", func(ctx context.Context, w *txClosureWorld, u *models.User) error {
		matched, err := w.fs.UpdateUserIfActiveStateMatches(ctx, u, u.IsActive)
		if err == nil && !matched {
			return fmt.Errorf("conditional update matched no row")
		}
		return err
	}},
}

func TestLocalStorage_UserUpdateUniqueViolationsAreTyped(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		seedRenameUser(t, w, "taken")
		for _, p := range updatePaths {
			t.Run(p.name, func(t *testing.T) {
				victim := seedRenameUser(t, w, "victim"+p.name)

				renamed := *victim
				renamed.Username, renamed.UsernameFolded = "TAKEN", "taken"
				err := p.write(ctx, w, &renamed)
				assert.ErrorIs(t, err, storage.ErrDuplicateUsername)
				assert.NotErrorIs(t, err, storage.ErrDuplicateEmail)

				reEmailed := *victim
				reEmailed.Email, reEmailed.EmailFolded = "Taken@example.com", "taken@example.com"
				err = p.write(ctx, w, &reEmailed)
				assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
				assert.NotErrorIs(t, err, storage.ErrDuplicateUsername)

				// Effect: neither refused write changed the row.
				var got models.User
				require.NoError(t, w.db.First(&got, victim.ID).Error)
				assert.Equal(t, victim.UsernameFolded, got.UsernameFolded)
				assert.Equal(t, victim.EmailFolded, got.EmailFolded)
			})
		}
	})
}

// A concurrent rename of two users to one free name: the pre-check cannot tell them
// apart, so both reach the index. Exactly one write wins; the loser gets the typed
// sentinel (not a storage failure carrying the constraint text) and keeps its old
// name. Real concurrent writers on the production schema, SQLite and Postgres; no
// hook makes either of them miss anything.
func TestLocalStorage_UsernameRenameRace_TwoWriters(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		for _, p := range updatePaths {
			t.Run(p.name, func(t *testing.T) {
				const rounds = 10
				for round := range rounds {
					contested := fmt.Sprintf("contested%s%d", p.name, round)
					users := []*models.User{
						seedRenameUser(t, w, fmt.Sprintf("raceA%s%d", p.name, round)),
						seedRenameUser(t, w, fmt.Sprintf("raceB%s%d", p.name, round)),
					}
					errs := make([]error, len(users))
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i, u := range users {
						wg.Go(func() {
							renamed := *u
							renamed.Username, renamed.UsernameFolded = contested, contested
							<-start
							errs[i] = p.write(ctx, w, &renamed)
						})
					}
					close(start)
					wg.Wait()

					winners, losers := 0, 0
					for i, err := range errs {
						if err == nil {
							winners++
							continue
						}
						losers++
						assert.ErrorIs(t, err, storage.ErrDuplicateUsername, "round %d writer %d: %v", round, i, err)
						var got models.User
						require.NoError(t, w.db.First(&got, users[i].ID).Error)
						assert.Equal(t, users[i].UsernameFolded, got.UsernameFolded, "the loser keeps its old name")
					}
					assert.Equal(t, 1, winners, "round %d: exactly one rename wins", round)
					assert.Equal(t, 1, losers, "round %d: the other is refused", round)

					var n int64
					require.NoError(t, w.db.Model(&models.User{}).Where("username_folded = ?", contested).Count(&n).Error)
					assert.Equal(t, int64(1), n, "round %d: one user holds the contested name", round)
				}
			})
		}
	})
}
