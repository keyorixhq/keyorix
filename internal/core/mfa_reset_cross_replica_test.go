package core

import (
	"context"
	"path/filepath"
	"sync"
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

func runMFAResetCrossReplicaApproval(t *testing.T, open func() *gorm.DB, migrate bool) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	ctx := context.Background()
	clock := &crossReplicaClock{t: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)}
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	newReplica := func(db *gorm.DB) (*KeyorixCore, *store.LocalStorage) {
		st := store.NewLocalStorage(db)
		c := NewKeyorixCore(st)
		c.SetAuthEncryptor(enc)
		c.now = clock.now
		return c, st
	}

	setupDB := open()
	if migrate {
		require.NoError(t, kxstorage.MigrateExisting(setupDB))
	}
	setup, setupSt := newReplica(setupDB)
	setup.SetBootstrapToken("test-bootstrap-token")
	_, err := setup.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)

	admin, err := setupSt.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	roleIDs, err := setupSt.GetUserRoleIDsAt(ctx, admin.ID, storage.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, roleIDs)

	secrets := map[uint]string{}
	enrol := func(uid uint, password string) {
		_, secret, err := setup.BeginMFAEnrollment(ctx, uid)
		require.NoError(t, err)
		secrets[uid] = secret
		code, err := totp.GenerateCode(secret, clock.step())
		require.NoError(t, err)
		_, err = setup.ActivateMFA(ctx, uid, code, password, "")
		require.NoError(t, err)
	}
	mk := func(name string, isAdmin bool) *models.User {
		u, err := setup.CreateUser(ctx, &CreateUserRequest{Username: name, Email: name + "@example.com", DisplayName: name, Password: mfaResetUserPassword})
		require.NoError(t, err)
		if isAdmin {
			require.NoError(t, setupSt.AssignRole(ctx, u.ID, roleIDs[0], storage.Scope{}))
		}
		return u
	}
	adminB := mk("admin-b", true)
	adminC := mk("admin-c", true)
	target := mk("target", false)
	enrol(admin.ID, "BootstrapPass123!")
	for _, u := range []*models.User{adminB, adminC, target} {
		enrol(u.ID, mfaResetUserPassword)
	}

	// Admin A (the bootstrap admin) opens the request; B and C will race to approve.
	codeA, err := totp.GenerateCode(secrets[admin.ID], clock.step())
	require.NoError(t, err)
	req, err := setup.RequestMFAReset(ctx, admin.ID, false, MFAResetRequestInput{
		User: "target", Reason: "lost phone", VerifiedBy: "video", Evidence: "call with T.", Code: codeA,
	})
	require.NoError(t, err)

	// Two replicas, each with its own connection; one fresh code per approver for the
	// same instant.
	coreB, _ := newReplica(open())
	coreC, _ := newReplica(open())
	racers := []struct {
		core *KeyorixCore
		id   uint
		code string
	}{{coreB, adminB.ID, ""}, {coreC, adminC.ID, ""}}
	at := clock.step()
	for i := range racers {
		racers[i].code, err = totp.GenerateCode(secrets[racers[i].id], at)
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	approvals := make([]*MFAResetApproval, len(racers))
	errs := make([]error, len(racers))
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			approvals[i], errs[i] = racers[i].core.ApproveMFAReset(ctx, racers[i].id, false, req.ID, racers[i].code)
		}()
	}
	close(start)
	wg.Wait()

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
	require.NotNil(t, approvals[winner])
	assert.Nil(t, approvals[loser], "the loser was handed a one-time password")

	// Verify from a fresh connection that shares nothing with the racers.
	vSt := store.NewLocalStorage(open())

	decided, err := vSt.GetMFAResetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, models.MFAResetStatusApproved, decided.Status)
	assert.Equal(t, racers[winner].id, decided.DecidedBy, "the recorded approver is not the winner")

	eff := approvals[winner].Effect
	assert.True(t, eff.TOTPCleared)
	sec, err := vSt.GetMFASecret(ctx, target.ID)
	assert.True(t, err != nil || sec == nil, "TOTP secret survived the reset")
	n, err := vSt.CountUnusedMFARecoveryCodes(ctx, target.ID)
	require.NoError(t, err)
	assert.Zero(t, n, "recovery codes survived the reset")
	u, err := vSt.GetUser(ctx, target.ID)
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
