package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTHZ-ORACLE-TAILS-1 item 2: every create/rename entry point that maps the email
// sentinel maps the username one too, so the loser of a race on the users username
// index answers "already exists" (REST 409 / gRPC AlreadyExists / SCIM 409 uniqueness)
// instead of a storage failure carrying the constraint text. The race is made
// deterministic the way TestCreateUser_UsernameRaceLoserGetsAlreadyExists does it: the
// winner's row is committed and the loser's name pre-check is made to miss it. Each
// test asserts the EFFECT (no row, grant or audit event left by the loser), not only
// the returned error. Production schema, SQLite and Postgres.

// racePathWorld is a bootstrapped install (roles seeded, one admin) plus a committed
// winner holding the username "racer" and the email "winner@example.com".
type racePathWorld struct {
	*txClosureWorld
	adminID uint
}

func newRacePathWorld(t *testing.T, w *txClosureWorld) *racePathWorld {
	t.Helper()
	w.c.SetBootstrapToken("test-bootstrap-token")
	res, err := w.c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	var admin models.User
	require.NoError(t, w.db.Where("username_folded = ?", "admin").First(&admin).Error)
	require.NoError(t, w.db.Create(&models.User{
		Username: "Racer", UsernameFolded: "racer", Email: "winner@example.com", EmailFolded: "winner@example.com",
		IsActive: true, AccountState: AccountActive,
	}).Error)
	return &racePathWorld{txClosureWorld: w, adminID: admin.ID}
}

// racingCore is a core over the same storage whose username pre-check misses the
// winner's committed row.
func (w *racePathWorld) racingCore() *KeyorixCore {
	return NewKeyorixCore(hooked(w.fs, &storeHooks{
		WrapTx: true,
		GetUserByUsername: func(_ storage.Storage, _ context.Context, _ string) (*models.User, error) {
			return nil, fmt.Errorf("lookup: %w", storage.ErrUserNotFound)
		},
	}))
}

// missEmailPreCheck makes the next GetUserByEmail answer "not found", as it would
// before the winner committed.
func (w *racePathWorld) missEmailPreCheck(t *testing.T) {
	t.Helper()
	w.fs.Arm(&faultstorage.FaultSpec{Method: "GetUserByEmail", NthCall: 1, Kind: faultstorage.KindError,
		Err: fmt.Errorf("lookup: %w", storage.ErrUserNotFound)})
}

func (w *racePathWorld) count(t *testing.T, model any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(model).Where(query, args...).Count(&n).Error)
	return n
}

func (w *racePathWorld) countAll(t *testing.T, model any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Unscoped().Model(model).Count(&n).Error)
	return n
}

func (w *racePathWorld) seedLoser(t *testing.T) *models.User {
	t.Helper()
	u := &models.User{
		Username: "bob", UsernameFolded: "bob", Email: "bob@example.com", EmailFolded: "bob@example.com",
		IsActive: true, AccountState: AccountActive,
	}
	require.NoError(t, w.db.Create(u).Error)
	return u
}

// UpdateUser (REST PATCH /users/{id}, gRPC UpdateUser, CLI): the rename and the email
// change both answer ErrUserAlreadyExists, and the loser's row and audit trail are
// untouched.
func TestUpdateUser_RaceLoserAnswersAlreadyExistsAndWritesNothing(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, base *txClosureWorld) {
		w := newRacePathWorld(t, base)
		loser := w.seedLoser(t)
		for name, req := range map[string]*UpdateUserRequest{
			"rename": {ID: loser.ID, ActorID: w.adminID, Username: "racer"},
			"email":  {ID: loser.ID, ActorID: w.adminID, Email: "winner@example.com"},
		} {
			t.Run(name, func(t *testing.T) {
				updatedBefore := w.auditCount(t, EventUserUpdated)
				if req.Email != "" {
					w.missEmailPreCheck(t)
				}
				_, err := w.racingCore().UpdateUser(context.Background(), req)
				if req.Email != "" {
					require.True(t, w.fs.Fired(), "the email pre-check was not reached")
				}
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUserAlreadyExists, "the race loser must get the winner's answer: %v", err)
				assert.NotContains(t, err.Error(), "username_folded", "the raw constraint text must not reach the caller")
				assert.NotContains(t, err.Error(), "email_folded", "the raw constraint text must not reach the caller")

				var got models.User
				require.NoError(t, w.db.First(&got, loser.ID).Error)
				assert.Equal(t, "bob", got.UsernameFolded, "the refused rename changed nothing")
				assert.Equal(t, "bob@example.com", got.EmailFolded, "the refused email change changed nothing")
				assert.Equal(t, updatedBefore, w.auditCount(t, EventUserUpdated), "the loser left no user.updated row")
				assert.Equal(t, int64(1), w.count(t, &models.User{}, "username_folded = ?", "racer"))
			})
		}
		// Control: the audit count above is not vacuously flat. A rename to a free name
		// applies and writes its user.updated row.
		t.Run("control_free_name", func(t *testing.T) {
			updatedBefore := w.auditCount(t, EventUserUpdated)
			_, err := w.c.UpdateUser(context.Background(), &UpdateUserRequest{ID: loser.ID, ActorID: w.adminID, Username: "robert"})
			require.NoError(t, err)
			assert.Equal(t, updatedBefore+1, w.auditCount(t, EventUserUpdated))
			var got models.User
			require.NoError(t, w.db.First(&got, loser.ID).Error)
			assert.Equal(t, "robert", got.UsernameFolded)
		})
	})
}

// SCIM provisioning derives the account's username (deriveSCIMUsername) with the same
// check-then-act read; the loser answers ErrSCIMUserExists (SCIM 409 uniqueness) and
// leaves no user, no baseline grant and no provisioning audit event: the user row and
// its grant commit together.
func TestProvisionSCIMUser_UsernameRaceLoserLeavesNothing(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, base *txClosureWorld) {
		w := newRacePathWorld(t, base)
		users, grants := w.countAll(t, &models.User{}), w.countAll(t, &models.UserRole{})
		provisioned := w.auditCount(t, EventSCIMUserProvisioned)

		// userName "racer@loser.example.com" derives the username "racer", the winner's.
		_, err := w.racingCore().ProvisionSCIMUser(context.Background(), 0,
			"racer@loser.example.com", "Loser", "racer@loser.example.com", "idp-loser", true)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSCIMUserExists, "race loser: %v", err)

		assert.Equal(t, users, w.countAll(t, &models.User{}), "no user row left behind")
		assert.Equal(t, grants, w.countAll(t, &models.UserRole{}), "no baseline grant left behind")
		assert.Equal(t, provisioned, w.auditCount(t, EventSCIMUserProvisioned), "no provisioning event for a refused account")
		assert.Zero(t, w.count(t, &models.User{}, "email_folded = ?", "racer@loser.example.com"))
	})
}

// SSO JIT provisioning derives its username the same way (deriveSCIMUsername). The loser
// gets a clean "already exists" error, not "Storage failed: <constraint text>", and no
// half-created account (no user, no default-role grant, no JIT audit event).
func TestProvisionSSOUser_UsernameRaceLoserLeavesNothing(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, base *txClosureWorld) {
		w := newRacePathWorld(t, base)
		users, grants := w.countAll(t, &models.User{}), w.countAll(t, &models.UserRole{})
		jit := w.auditCount(t, EventSSOJITProvision)

		_, err := w.racingCore().provisionSSOUser(context.Background(),
			&SSOProvider{Name: "okta", AutoProvision: true}, "okta|loser", "racer@loser.example.com", true, "Loser")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "a user with this username already exists")
		assert.NotContains(t, err.Error(), "username_folded", "the raw constraint text must not reach the caller")
		assert.NotContains(t, err.Error(), "Storage failed")

		assert.Equal(t, users, w.countAll(t, &models.User{}), "no user row left behind")
		assert.Equal(t, grants, w.countAll(t, &models.UserRole{}), "no default-role grant left behind")
		assert.Equal(t, jit, w.auditCount(t, EventSSOJITProvision), "no JIT event for a refused account")
	})
}
