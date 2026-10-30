package core

// concurrency_create_user_username_race_postgres_test.go -- ERRLOSS-TAILS-2 item 2.
//
// CreateUser's username pre-check (GetUserByUsername) is a read followed by a later write, so
// two creators on two replicas can both pass it before either commits. The partial unique index
// uniq_users_username_folded_active then fails the loser's INSERT, which AUTHZ-ORACLE-1 (#3815)
// types as storage.ErrDuplicateUsername and core answers as ErrUserAlreadyExists (HTTP 409 /
// gRPC AlreadyExists). #3815's TestCreateUser_UsernameRaceLoserGetsAlreadyExists simulates the
// loser on ONE storage (its pre-check is made to miss a committed row); this is the real
// cross-replica shape: two independent *gorm.DB connections, both inserts in flight.
//
// The race is forced, not hoped for: a hook on each replica's GetUserByUsername holds the
// result until BOTH replicas have done their pre-check, so both are guaranteed to pass it.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// usernamePrecheckBarrier makes every GetUserByUsername caller wait (up to 10 s) until `parties`
// callers have performed their lookup, so all of them see the state from before any create.
type usernamePrecheckBarrier struct {
	mu      sync.Mutex
	parties int
	arrived int
	release chan struct{}
}

func newUsernamePrecheckBarrier(parties int) *usernamePrecheckBarrier {
	return &usernamePrecheckBarrier{parties: parties, release: make(chan struct{})}
}

func (b *usernamePrecheckBarrier) hooks() *storeHooks {
	return &storeHooks{GetUserByUsername: func(next storage.Storage, ctx context.Context, name string) (*models.User, error) {
		u, err := next.GetUserByUsername(ctx, name)
		b.mu.Lock()
		b.arrived++
		if b.arrived == b.parties {
			close(b.release)
		}
		b.mu.Unlock()
		select {
		case <-b.release:
		case <-time.After(10 * time.Second):
		}
		return u, err
	}}
}

func (b *usernamePrecheckBarrier) allArrived() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrived >= b.parties
}

func TestConcurrency_CreateUser_CrossReplicaPostgres_DuplicateUsernameIsAlreadyExists(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(append(sodGrantModels, &models.PasswordHistory{})...))
	// AutoMigrate does not create the partial unique index (factory.go's ensureUserUsernameIndex
	// does, at startup); the same DDL, or the race has nothing to collide on.
	require.NoError(t, setupDB.Exec("CREATE UNIQUE INDEX uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL").Error)
	ctx := context.Background()

	barrier := newUsernamePrecheckBarrier(2)
	dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
	defer closePG(dbA)
	defer closePG(dbB)
	coreA := NewKeyorixCore(hooked(localstore.NewLocalStorage(dbA), barrier.hooks()))
	coreB := NewKeyorixCore(hooked(localstore.NewLocalStorage(dbB), barrier.hooks()))

	// Same username, different emails: only the username index can collide.
	res := raceReplicas(t,
		func() error {
			_, err := coreA.CreateUser(ctx, &CreateUserRequest{Username: "racer", Email: "racer-a@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
			return err
		},
		func() error {
			_, err := coreB.CreateUser(ctx, &CreateUserRequest{Username: "racer", Email: "racer-b@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
			return err
		},
	)
	t.Logf("creator A: %v / creator B: %v", res.ErrA, res.ErrB)

	require.True(t, barrier.allArrived(), "both creators must have passed the username pre-check before either wrote, or this is not the race")
	var winners, losers int
	for _, err := range []error{res.ErrA, res.ErrB} {
		if err == nil {
			winners++
			continue
		}
		losers++
		assert.ErrorIs(t, err, ErrUserAlreadyExists, "the loser must be answered as already-exists (409 / AlreadyExists), not an internal error")
	}
	assert.Equal(t, 1, winners, "exactly one creator wins")
	assert.Equal(t, 1, losers)

	// Effect, from a fresh connection: exactly one live row carries the username.
	var n int64
	require.NoError(t, pgOpen(t, dsn).Model(&models.User{}).Where("username_folded = ?", "racer").Count(&n).Error)
	assert.Equal(t, int64(1), n, "exactly one account may own the username")
}
