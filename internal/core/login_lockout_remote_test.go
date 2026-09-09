// login_lockout_remote_test.go — apiOKUser (shared with password_remote_test.go,
// #484) and TestLockout_UnsupportedBackendStillFailsOpenLoudly, login_lockout.go's
// fail-open-loudly defense in depth for any storage.Storage backend that cannot
// satisfy UpdateLoginLockoutState.
//
// This file used to also carry #529's RemoteStorage regression coverage
// (TestLockout_RemoteStorageGenuinelyPersistsAndLocks/_Clears,
// TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits), proving
// recordFailedLogin/checkLockAndClearLoginFailures/UnlockUser genuinely
// round-tripped over RemoteStorage to a real (test) HTTP server. Deleted along
// with UpdateLoginLockoutStateProxy in the G80 liveness sweep (see
// docs/g80-remediation-notes.md's "premise-impossible vs premise-true-but-
// unverified" distinction): those tests built *KeyorixCore{storage: rs} as a raw
// struct literal, bypassing internal/config.Config validation entirely — the
// topology they exercised (a server process backed by RemoteStorage) is rejected
// UNCONDITIONALLY by validateRemoteStorageNotServer (internal/config/config.go:2057)
// and cannot occur in any deployment: of RemoteStorage's 27 core.NewKeyorixCore
// call sites repo-wide, exactly one (server/main.go:317) ever reaches
// server/http/handlers, and both server/main.go's main() (line 75) and
// initializeCoreService() (line 302) call cfg.Validate() unconditionally before
// that point. The anti-silent-no-op guarantee these tests protected is preserved
// by different, still-live machinery: RemoteStorage.UpdateLoginLockoutState now
// returns errUnsupportedRemote (fails loudly, not silently) like every other
// known-unsupported RemoteStorage operation, and
// TestRemoteStorageWireCalls_HaveMatchingRoute (internal/storage/store) still
// catches any wire call left with no matching route.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// apiOKUser writes a successful envelope response wrapping user, matching the REAL
// wire shape server/http/handlers/users_handler.go's userToAPIResponse produces
// (snake_case keys) — not a raw models.User marshal. RemoteStorage.GetUser (and so
// LockUserForUpdate, which is just GetUser — see remote_users.go) decodes exactly
// this shape (#496); a raw-model mock would silently paper over the same
// request/response field-name mismatch #496 fixed, since both sides would share the
// identical (wrong) assumption. Shared with password_remote_test.go (#484), which
// also needs a stand-in GetUser response.
//
// failed_login_attempts/login_lockout_count/last_failed_login_at are part of that
// real shape (alongside login_locked_until), so this mock includes them
// unconditionally too — omitting them here would silently reintroduce the exact
// stale-mock blind spot #496's own fix was written to avoid.
func apiOKUser(t *testing.T, w http.ResponseWriter, user *models.User) {
	t.Helper()
	data := map[string]interface{}{
		"id":                    user.ID,
		"username":              user.Username,
		"email":                 user.Email,
		"display_name":          user.DisplayName,
		"active":                user.IsActive,
		"account_state":         user.AccountState,
		"created_at":            user.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":            user.UpdatedAt.UTC().Format(time.RFC3339),
		"last_login_at":         nil,
		"deleted_at":            nil,
		"failed_login_attempts": user.FailedLoginAttempts,
		"login_lockout_count":   user.LoginLockoutCount,
		"last_failed_login_at":  nil,
	}
	if user.LastLoginAt != nil {
		data["last_login_at"] = user.LastLoginAt.UTC().Format(time.RFC3339)
	}
	if user.LoginLockedUntil != nil {
		data["login_locked_until"] = user.LoginLockedUntil.UTC().Format(time.RFC3339)
	}
	if user.LastFailedLoginAt != nil {
		data["last_failed_login_at"] = user.LastFailedLoginAt.UTC().Format(time.RFC3339)
	}
	type resp struct {
		Success bool        `json:"success"`
		Data    interface{} `json:"data"`
	}
	require.NoError(t, json.NewEncoder(w).Encode(resp{Success: true, Data: data}))
}

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
