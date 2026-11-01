package core

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// MFA-RESET-TESTS-1: two administrators approve ONE MFA reset request at the same
// instant, each through its own replica (own *gorm.DB pool, own LocalStorage, own
// KeyorixCore, so the process-local accountStateMu of one cannot serialize the
// other). Whatever the interleaving, exactly one approval wins; the loser gets the
// typed ErrMFAResetRequestDecided and changes nothing; the target ends with one
// cleared second factor and exactly one mfa.reset audit row. The conditional
// transition in DecideMFAResetRequestIfPending is the only thing that can choose
// the winner, so this fails if it stops being conditional.

// crossReplicaClock is the one clock all replicas read, so a TOTP code minted for
// it validates on every replica.
type crossReplicaClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *crossReplicaClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// step advances one TOTP period (plus margin) so the next code is a never-used step.
func (c *crossReplicaClock) step() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(31 * time.Second)
	return c.t
}

// mfaResetWorld is a bootstrapped install shared by the cross-replica tests:
// global admins admin (A), admin-b, admin-c and the non-admin target, each with
// TOTP, over a database every replica opens its own connection pool to.
type mfaResetWorld struct {
	t       *testing.T
	clock   *crossReplicaClock
	enc     *encryption.Service
	open    func() *gorm.DB
	setup   *KeyorixCore
	secrets map[uint]string

	admin, adminB, adminC, target *models.User
}

func newMFAResetWorld(t *testing.T, open func() *gorm.DB, migrate bool) *mfaResetWorld {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	ctx := context.Background()
	w := &mfaResetWorld{
		t: t, open: open, secrets: map[uint]string{},
		clock: &crossReplicaClock{t: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)},
	}
	w.enc = encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, w.enc.Initialize("test-passphrase"))

	setupDB := open()
	if migrate {
		require.NoError(t, kxstorage.MigrateExisting(setupDB))
	}
	setupSt := store.NewLocalStorage(setupDB)
	w.setup = w.replicaOver(setupSt)
	w.setup.SetBootstrapToken("test-bootstrap-token")
	_, err := w.setup.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	w.admin, err = setupSt.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	roleIDs, err := setupSt.GetUserRoleIDsAt(ctx, w.admin.ID, storage.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, roleIDs)

	enrol := func(uid uint, password string) {
		_, secret, err := w.setup.BeginMFAEnrollment(ctx, uid)
		require.NoError(t, err)
		w.secrets[uid] = secret
		_, err = w.setup.ActivateMFA(ctx, uid, w.code(uid, w.clock.step()), password, "")
		require.NoError(t, err)
	}
	mk := func(name string, isAdmin bool) *models.User {
		u, err := w.setup.CreateUser(ctx, &CreateUserRequest{Username: name, Email: name + "@example.com", DisplayName: name, Password: mfaResetUserPassword})
		require.NoError(t, err)
		if isAdmin {
			require.NoError(t, setupSt.AssignRole(ctx, u.ID, roleIDs[0], storage.Scope{}))
		}
		return u
	}
	w.adminB = mk("admin-b", true)
	w.adminC = mk("admin-c", true)
	w.target = mk("target", false)
	enrol(w.admin.ID, "BootstrapPass123!")
	for _, u := range []*models.User{w.adminB, w.adminC, w.target} {
		enrol(u.ID, mfaResetUserPassword)
	}
	return w
}

func (w *mfaResetWorld) replicaOver(st storage.Storage) *KeyorixCore {
	c := NewKeyorixCore(st)
	c.SetAuthEncryptor(w.enc)
	c.now = w.clock.now
	return c
}

// replica is a new replica on its own connection pool; wrap (optional) wraps its
// storage, given the replica's own LocalStorage.
func (w *mfaResetWorld) replica(wrap func(base storage.Storage) storage.Storage) *KeyorixCore {
	var st storage.Storage = store.NewLocalStorage(w.open())
	if wrap != nil {
		st = wrap(st)
	}
	return w.replicaOver(st)
}

func (w *mfaResetWorld) code(uid uint, at time.Time) string {
	w.t.Helper()
	code, err := totp.GenerateCode(w.secrets[uid], at)
	require.NoError(w.t, err)
	return code
}

// mfaResetBarrier holds the first of two parties until the second arrives or
// wait elapses. together reports whether both were inside it at once.
type mfaResetBarrier struct {
	mu       sync.Mutex
	arrived  int
	both     chan struct{}
	wait     time.Duration
	together bool
}

func newMFAResetBarrier(wait time.Duration) *mfaResetBarrier {
	return &mfaResetBarrier{both: make(chan struct{}), wait: wait}
}

func (b *mfaResetBarrier) arrive() {
	b.mu.Lock()
	b.arrived++
	n := b.arrived
	if n == 2 {
		close(b.both)
	}
	b.mu.Unlock()
	if n != 1 {
		return
	}
	select {
	case <-b.both:
		b.mu.Lock()
		b.together = true
		b.mu.Unlock()
	case <-time.After(b.wait):
	}
}

func (b *mfaResetBarrier) state() (arrived int, together bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrived, b.together
}

func runMFAResetCrossReplicaApproval(t *testing.T, open func() *gorm.DB, migrate bool) {
	t.Helper()
	ctx := context.Background()
	w := newMFAResetWorld(t, open, migrate)
	vSt := store.NewLocalStorage(open())

	// Admin A (the bootstrap admin) opens the request; B and C will race to approve.
	req, err := w.setup.RequestMFAReset(ctx, w.admin.ID, false, MFAResetRequestInput{
		User: "target", Reason: "lost phone", VerifiedBy: "video", Evidence: "call with T.", Code: w.code(w.admin.ID, w.clock.step()),
	})
	require.NoError(t, err)

	// #3801 (c): both approvers are held after the pre-transaction status read
	// until both have made it, so both see the request pending and neither can be
	// refused before its transaction; only DecideMFAResetRequestIfPending, inside
	// it, can choose the winner. Each replica records what its decision returned.
	readBarrier := newMFAResetBarrier(30 * time.Second)
	var decided [2]atomic.Int32 // 0: not called, 1: matched, 2: not matched
	wrapRacer := func(i int) func(storage.Storage) storage.Storage {
		return func(base storage.Storage) storage.Storage {
			return hooked(base, &storeHooks{
				WrapTx: true,
				GetMFAResetRequest: func(next storage.Storage, ctx context.Context, id uint) (*models.MFAResetRequest, error) {
					r, err := next.GetMFAResetRequest(ctx, id)
					if next == base && id == req.ID {
						readBarrier.arrive()
					}
					return r, err
				},
				DecideMFAResetRequestIfPending: func(next storage.Storage, ctx context.Context, id uint, status string, by uint, now time.Time) (bool, error) {
					matched, err := next.DecideMFAResetRequestIfPending(ctx, id, status, by, now)
					if err == nil && id == req.ID {
						decided[i].Store(map[bool]int32{true: 1, false: 2}[matched])
					}
					return matched, err
				},
			})
		}
	}

	// Two replicas, each with its own connection; one fresh code per approver for the
	// same instant.
	racers := []struct {
		core *KeyorixCore
		id   uint
		code string
	}{{w.replica(wrapRacer(0)), w.adminB.ID, ""}, {w.replica(wrapRacer(1)), w.adminC.ID, ""}}
	at := w.clock.step()
	for i := range racers {
		racers[i].code = w.code(racers[i].id, at)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	approvals := make([]*MFAResetApproval, len(racers))
	errs := make([]error, len(racers))
	for i := range racers {
		wg.Go(func() {
			<-start
			approvals[i], errs[i] = racers[i].core.ApproveMFAReset(ctx, racers[i].id, false, req.ID, racers[i].code)
		})
	}
	close(start)
	wg.Wait()

	arrived, together := readBarrier.state()
	require.Equal(t, 2, arrived, "both approvers must make the pre-transaction status read")
	require.True(t, together, "the approvers were not both past the pre-transaction read at once: the race was not forced")

	winner := -1
	for i := range racers {
		if errs[i] == nil {
			require.Equal(t, -1, winner, "both approvals of one request succeeded")
			winner = i
		}
	}
	require.NotEqual(t, -1, winner, "no approval won: %v / %v", errs[0], errs[1])
	loser := 1 - winner
	require.ErrorIs(t, errs[loser], ErrMFAResetRequestDecided, "the loser must get the typed already-decided error")
	assert.EqualValues(t, 1, decided[winner].Load(), "the winner's conditional transition must have matched")
	assert.EqualValues(t, 2, decided[loser].Load(),
		"the loser's refusal must come from DecideMFAResetRequestIfPending inside its transaction, not from a pre-transaction read")
	require.NotNil(t, approvals[winner])
	assert.Nil(t, approvals[loser], "the loser was handed a one-time password")

	// Verify from a fresh connection that shares nothing with the racers.
	decidedReq, err := vSt.GetMFAResetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, models.MFAResetStatusApproved, decidedReq.Status)
	assert.Equal(t, racers[winner].id, decidedReq.DecidedBy, "the recorded approver is not the winner")

	eff := approvals[winner].Effect
	assert.True(t, eff.TOTPCleared)
	sec, err := vSt.GetMFASecret(ctx, w.target.ID)
	assert.True(t, err != nil || sec == nil, "TOTP secret survived the reset")
	n, err := vSt.CountUnusedMFARecoveryCodes(ctx, w.target.ID)
	require.NoError(t, err)
	assert.Zero(t, n, "recovery codes survived the reset")
	u, err := vSt.GetUser(ctx, w.target.ID)
	require.NoError(t, err)
	assert.False(t, u.MFAEnabled)
	assert.True(t, u.MFAEnrolmentRequired)
	// Exactly one one-time password exists, and it is the winner's: the loser cannot
	// have replaced it with a second one.
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(approvals[winner].OneTimePassword)),
		"the stored password is not the winner's one-time password")
	assert.Error(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(mfaResetUserPassword)),
		"the old password still works after the reset")

	for event, want := range map[string]int{EventMFAReset: 1} {
		logs, _, err := vSt.GetAuditLogs(ctx, &storage.AuditFilter{Actions: []string{event}})
		require.NoError(t, err)
		assert.Len(t, logs, want, "audit rows of %s", event)
	}
}

// #3801 (a): two admins request a reset of the same target at once, each on its
// own replica. Both pass the pre-transaction "already pending" read (held at a
// barrier on the requester's code check until both have), and inside the create
// transaction each is held again at a barrier right before the in-transaction
// pending read. Only tx.LockUserForUpdate on the target's row (mfa_reset.go,
// RequestMFAReset) stands between them: with it, the second transaction cannot
// reach that read until the first committed, so the in-transaction barrier never
// holds both at once and the second request sees the first and is refused.
// Postgres only: SQLite's BEGIN IMMEDIATE serializes the whole transaction, so the
// row lock is not what decides there.
func TestMFAReset_ConcurrentRequestsForSameTarget_CrossReplicaPostgres_RowLockDecides(t *testing.T) {
	res := runMFAResetConcurrentRequests(t, false)
	require.Equal(t, 2, res.inTxArrived, "both create transactions must reach the in-transaction pending read")
	assert.False(t, res.inTxTogether,
		"both create transactions were inside, before the pending read, at once: nothing serialized them on the target's row")
	for _, err := range res.errs {
		if err != nil {
			require.ErrorIs(t, err, ErrMFAResetAlreadyPending)
		}
	}
	require.Equal(t, 1, res.succeeded, "exactly one of two concurrent requests for one target may succeed: %v", res.errs)
	assert.Equal(t, 1, res.pending, "two requests for one target are pending")
}

// Calibration of the test above (red without the lock, no production edit): the
// same choreography with the target's row lock taken away by the test hook (the
// in-transaction LockUserForUpdate of the target answers with a plain read). Both
// transactions are then held at the in-transaction barrier together, both read no
// pending request and both insert, so the assertions above would fail. This is
// what shows the lock, not the barrier timing, decides the test.
func TestMFAReset_ConcurrentRequestsForSameTarget_CrossReplicaPostgres_Calibration_NoLockTwoPending(t *testing.T) {
	res := runMFAResetConcurrentRequests(t, true)
	assert.True(t, res.inTxTogether, "without the row lock both transactions reach the pending read at once")
	assert.Equal(t, 2, res.succeeded, "without the row lock both requests succeed: %v", res.errs)
	assert.Equal(t, 2, res.pending, "without the row lock two requests for one target are pending")
}

type mfaResetConcurrentRequestsResult struct {
	inTxArrived  int
	inTxTogether bool
	errs         []error
	succeeded    int
	pending      int
}

func runMFAResetConcurrentRequests(t *testing.T, dropTargetLock bool) mfaResetConcurrentRequestsResult {
	t.Helper()
	base := pgTestDSN(t)
	dsn := pgMigratedDatabaseDSN(t, base)
	open := func() *gorm.DB { return pgOpen(t, dsn) }
	ctx := context.Background()
	w := newMFAResetWorld(t, open, false)

	codeBarrier := newMFAResetBarrier(30 * time.Second)
	inTxBarrier := newMFAResetBarrier(3 * time.Second)
	wrap := func(base storage.Storage) storage.Storage {
		hooks := &storeHooks{
			WrapTx: true,
			MarkTOTPStepUsed: func(next storage.Storage, ctx context.Context, userID uint, step int64) (bool, error) {
				if next == base {
					codeBarrier.arrive()
				}
				return next.MarkTOTPStepUsed(ctx, userID, step)
			},
			ListMFAResetRequests: func(next storage.Storage, ctx context.Context, pendingOnly bool) ([]*models.MFAResetRequest, error) {
				if next != base {
					inTxBarrier.arrive()
				}
				return next.ListMFAResetRequests(ctx, pendingOnly)
			},
		}
		if dropTargetLock {
			hooks.LockUserForUpdate = func(next storage.Storage, ctx context.Context, id uint) (*models.User, error) {
				if next != base && id == w.target.ID {
					return next.GetUser(ctx, id)
				}
				return next.LockUserForUpdate(ctx, id)
			}
		}
		return hooked(base, hooks)
	}
	requesters := []struct {
		core *KeyorixCore
		id   uint
		code string
	}{{w.replica(wrap), w.admin.ID, ""}, {w.replica(wrap), w.adminC.ID, ""}}
	at := w.clock.step()
	for i := range requesters {
		requesters[i].code = w.code(requesters[i].id, at)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	res := mfaResetConcurrentRequestsResult{errs: make([]error, len(requesters))}
	for i := range requesters {
		wg.Go(func() {
			<-start
			_, res.errs[i] = requesters[i].core.RequestMFAReset(ctx, requesters[i].id, false, MFAResetRequestInput{
				User: "target", Reason: "lost phone", VerifiedBy: "ticket", Code: requesters[i].code,
			})
		})
	}
	close(start)
	wg.Wait()

	arrived, together := codeBarrier.state()
	require.Equal(t, 2, arrived)
	require.True(t, together, "both requests must pass the pre-transaction pending read before either transaction starts")
	res.inTxArrived, res.inTxTogether = inTxBarrier.state()
	for _, err := range res.errs {
		if err == nil {
			res.succeeded++
		}
	}
	pending, err := store.NewLocalStorage(open()).ListMFAResetRequests(ctx, true)
	require.NoError(t, err)
	res.pending = len(pending)
	return res
}

func TestMFAReset_TwoAdminsApproveAtOnce_CrossReplicaPostgres_ExactlyOneWins(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgMigratedDatabaseDSN(t, base)
	runMFAResetCrossReplicaApproval(t, func() *gorm.DB { return pgOpen(t, dsn) }, false)
}

// SQLite is single-writer: the two approvals serialize on the database write lock
// (production pragmas, BEGIN IMMEDIATE), so the loser sees the committed decision.
// The assertions are the same.
func TestMFAReset_TwoAdminsApproveAtOnce_CrossReplicaSQLite_ExactlyOneWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa-reset-cross-replica.db")
	runMFAResetCrossReplicaApproval(t, func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open("file:"+path+sqliteProdPragmas), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		t.Cleanup(func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		})
		return db
	}, true)
}
