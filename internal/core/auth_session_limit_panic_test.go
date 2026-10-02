// auth_session_limit_panic_test.go — regression test for #2425: mintSession's
// EnforceSessionLimit call ran after CreateSession had already committed the
// new session row. Its best-effort handling covered a RETURNED error
// (`_ = ...`) but had no recover() for a panic — a panic there propagated
// through Login/VerifyMFALogin/etc. past the point of commit, reporting an
// already-successful login as a failed request, same shape as #2449's
// projectCounts finding (server/grpc/services/user_service.go).
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// enforceSessionLimitPanicStub wraps a real storage.Storage and makes
// EnforceSessionLimit panic, mirroring the countProjectMembershipsPanicStub
// pattern in server/grpc/services/user_service_projectcounts_panic_test.go.
type enforceSessionLimitPanicStub struct {
	storage.Storage
}

func (s *enforceSessionLimitPanicStub) EnforceSessionLimit(ctx context.Context, userID uint, keep int) error {
	panic("fault-fuzz injected failure")
}

// TestLogin_EnforceSessionLimitPanicDoesNotMaskSuccess: a panic from
// EnforceSessionLimit (reached via mintSession, after CreateSession has
// already committed the session row) must not report Login as failed.
func TestLogin_EnforceSessionLimitPanicDoesNotMaskSuccess(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))
	hash, err := bcrypt.GenerateFromPassword([]byte(lockoutTestPassword), int(bcryptCost.Load()))
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "bob", UsernameFolded: "bob", PasswordHash: string(hash), AccountState: AccountActive}).Error)

	c := &KeyorixCore{
		storage:        &enforceSessionLimitPanicStub{Storage: store.NewLocalStorage(db)},
		now:            time.Now,
		passwordPolicy: DefaultPasswordPolicy(),
	}

	session, user, err := c.Login(context.Background(), &LoginRequest{Username: "bob", Password: lockoutTestPassword})
	require.NoError(t, err, "a panic in the post-commit EnforceSessionLimit call must not fail Login")
	require.NotNil(t, session)
	require.NotNil(t, user)
	assert.Equal(t, "bob", user.Username)

	// The session genuinely exists afterward -- this was a real commit, not
	// an error that happened to return a populated-looking response.
	stored, err := store.NewLocalStorage(db).GetSession(context.Background(), session.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, uint(1), stored.UserID)
}
