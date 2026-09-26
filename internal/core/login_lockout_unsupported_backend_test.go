// login_lockout_unsupported_backend_test.go — TestLockout_UnsupportedBackendStillFailsOpenLoudly,
// login_lockout.go's fail-open-loudly defense in depth for any storage.Storage
// backend that cannot satisfy UpdateLoginLockoutState.
//
// This file used to also carry #529's RemoteStorage regression coverage
// (TestLockout_RemoteStorageGenuinelyPersistsAndLocks/_Clears,
// TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits, plus the apiOKUser
// helper shared with password_remote_test.go), proving
// recordFailedLogin/checkLockAndClearLoginFailures/UnlockUser genuinely
// round-tripped over RemoteStorage to a real (test) HTTP server. That RemoteStorage
// coverage was deleted along with UpdateLoginLockoutStateProxy in the G80 liveness
// sweep, and RemoteStorage itself (along with apiOKUser and password_remote_test.go)
// was deleted entirely in ADR-108 Phase 6 step 14b-2 -- what's left below is
// backend-agnostic defense in depth, unrelated to RemoteStorage specifically.
package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestLockout_UnsupportedBackendStillFailsOpenLoudly is defense in depth (mirroring
// rate_limit.go's identical #452 precedent): RemoteStorage itself no longer hits
// this path (see above), but isUnsupportedByBackend/warnLockoutUnsupportedOnce stay
// in login_lockout.go for any FUTURE storage.Storage implementation that genuinely
// cannot satisfy UpdateLoginLockoutState. A mock standing in for that hypothetical
// backend must still fail OPEN with exactly one loud operator warning, never block
// or repeat-log.
func TestLockout_UnsupportedBackendStillFailsOpenLoudly(t *testing.T) {
	m := new(MockStorage)
	uid := uint(7)
	user := &models.User{ID: uid, Username: "erin", AccountState: AccountActive, IsActive: true}
	// freshUnlockedUser returns a brand-new, never-mutated pointer reflecting the
	// pristine (never-actually-persisted) state — since the write always fails here,
	// nothing was genuinely written anywhere, so every fresh LockUserForUpdate read
	// must keep observing the SAME pristine row, never a previous call's in-memory-only
	// mutation of a shared/reused pointer (which would be a test artifact, not
	// something a real backend could ever produce).
	freshUnlockedUser := func() *models.User {
		return &models.User{ID: uid, Username: "erin", AccountState: AccountActive, IsActive: true}
	}
	// LockUserForUpdate (internal/core/mock_storage_test.go) delegates to the GetUser
	// expectation, not its own.
	m.On("UpdateLoginLockoutState", mock.Anything, uid, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fmt.Errorf("wrap: %w", storage.ErrUnsupportedByBackend))

	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 1, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	c := &KeyorixCore{storage: m, now: func() time.Time { return time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC) }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetLoginLockoutPolicy(policy)
	ctx := context.Background()

	out := captureLog(t, func() {
		m.On("GetUser", mock.Anything, uid).Return(freshUnlockedUser(), nil).Once()
		assert.NotPanics(t, func() { c.recordFailedLogin(ctx, user) })
	})
	assert.Contains(t, out, "login lockout accounting is INERT")
	assert.Nil(t, user.LoginLockedUntil, "must not claim a lock was applied when persistence failed")

	out2 := captureLog(t, func() {
		for i := 0; i < 5; i++ {
			m.On("GetUser", mock.Anything, uid).Return(freshUnlockedUser(), nil).Once()
			c.recordFailedLogin(ctx, user)
		}
	})
	assert.Empty(t, out2, "the warning must not repeat on subsequent calls")
}
