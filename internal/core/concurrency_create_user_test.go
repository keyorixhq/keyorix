package core_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestConcurrency_CreateUser_NoDuplicateEmail is the (#117) regression: models.User.Email
// previously had no DB-level unique index (unlike Username's `gorm:"uniqueIndex"`), so
// concurrent CreateUser calls with the identical email could all succeed, producing
// multiple rows sharing one email that GetUserByEmail then resolved to an arbitrary one
// of — a 100%-reproducible ambiguous login/identity-resolution bug (empirically confirmed:
// 5-8 of 10 concurrent inserts succeeded in every run). This drives many concurrent
// (*LocalStorage).CreateUser calls for the identical (case-varied) email against a real
// file-backed SQLite, with the same partial unique index production installs get (mirrors
// factory.go's ensureUserEmailIndex exactly), and asserts exactly one row survives, with
// every loser getting the clean ErrDuplicateEmail sentinel rather than a raw
// constraint-violation error or a silently-duplicated identity.
func TestConcurrency_CreateUser_NoDuplicateEmail(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "users.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	// Mirror factory.go's ensureUserEmailIndex exactly: a partial, case-insensitive
	// unique index on live rows, so this test exercises the same DB-level guard
	// production installs get, not just the (removed) in-process check-then-act read.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_email_active "+
		"ON users (LOWER(email)) WHERE deleted_at IS NULL AND email <> ''").Error)

	ls := store.NewLocalStorage(db)

	const attackers = 20 // many concurrent creates racing for the same email
	start := make(chan struct{})
	errs := make([]error, attackers)
	var wg sync.WaitGroup
	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Case-varied email + distinct usernames: the point is that email alone
			// must collide at the DB layer regardless of casing, even though every
			// other field differs — matching GetUserByEmail's own LOWER(email) lookup.
			email := "Bob@Example.com"
			if i%2 == 1 {
				email = "bob@example.com"
			}
			_, cerr := ls.CreateUser(context.Background(), &models.User{
				Username: fmt.Sprintf("bob%d", i),
				Email:    email,
			})
			errs[i] = cerr
		}(i)
	}
	close(start) // release every create at once
	wg.Wait()

	var successes, duplicateRejections int
	for _, cerr := range errs {
		if cerr == nil {
			successes++
			continue
		}
		if errors.Is(cerr, storage.ErrDuplicateEmail) {
			duplicateRejections++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent create must succeed")
	assert.Equal(t, attackers-1, duplicateRejections,
		"every other concurrent create must get the clean ErrDuplicateEmail sentinel, not a raw DB error")

	// And the DB must hold exactly one row for the email, regardless of casing — no
	// ambiguous duplicate identity from the TOCTOU window this closes.
	var count int64
	require.NoError(t, db.Model(&models.User{}).
		Where("LOWER(email) = LOWER(?)", "bob@example.com").
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "exactly one user row must exist for the email, regardless of casing")
}
