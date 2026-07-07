// login_lockout_remote_test.go — regression coverage for backlog #529:
// RemoteStorage.UpdateLoginLockoutState (internal/storage/store/remote_users.go)
// used to be a hard, permanent remoteUnsupported(...) stub (#454) — every
// recordFailedLogin/checkLockAndClearLoginFailures/clearLoginFailures/UnlockUser
// write in login_lockout.go silently failed OPEN under storage.type: remote,
// making per-account brute-force lockout accounting completely inert for that
// deployment mode. It is now a genuine thin passthrough onto a new
// PUT /api/v1/system/users/{id}/login-lockout route
// (server/http/handlers/login_lockout_proxy.go), so this file proves the
// accounting genuinely PERSISTS across the wire — not just that the call no
// longer errors.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

// fakeUpstreamLoginLockout is a minimal, in-memory stand-in for the real
// server-side login-lockout proxy (server/http/handlers/login_lockout_proxy.go,
// registered in server/http/router.go under
// /api/v1/system/users/{id}/login-lockout) PLUS the ordinary GET /api/v1/users/{id}
// route LockUserForUpdate uses. internal/core cannot import server/http (server/http
// imports internal/core — that would be a package cycle), so this hand-rolls the
// identical wire contract, matching the existing convention rate_limit_test.go's
// fakeUpstreamLoginAttempts already uses for the sibling #452 fix. The
// production-router version of the admin-unlock half of this scenario is
// TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits in server/http, which
// exercises the ACTUAL handler code, not this stand-in.
type fakeUpstreamLoginLockout struct {
	mu     sync.Mutex
	user   models.User
	events []string // audit event types recorded via POST /api/v1/audit/events
}

func newFakeUpstreamLoginLockout(user models.User) *fakeUpstreamLoginLockout {
	return &fakeUpstreamLoginLockout{user: user}
}

func (f *fakeUpstreamLoginLockout) snapshot() models.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.user
}

func (f *fakeUpstreamLoginLockout) auditEventTypes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeUpstreamLoginLockout) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// GET /api/v1/users/{id} — backs LockUserForUpdate/GetUser. Mirrors
	// userToAPIResponse's real snake_case wire shape (#496/#500) so this stand-in
	// can't paper over a field-name mismatch the same way the real handler couldn't.
	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		u := f.snapshot()
		data := map[string]interface{}{
			"id":                    u.ID,
			"username":              u.Username,
			"email":                 u.Email,
			"display_name":          u.DisplayName,
			"active":                u.IsActive,
			"account_state":         u.AccountState,
			"created_at":            time.Now().UTC().Format(time.RFC3339),
			"updated_at":            time.Now().UTC().Format(time.RFC3339),
			"last_login_at":         nil,
			"deleted_at":            nil,
			"failed_login_attempts": u.FailedLoginAttempts,
			"login_lockout_count":   u.LoginLockoutCount,
			"last_failed_login_at":  nil,
			"login_locked_until":    nil,
		}
		if u.LastFailedLoginAt != nil {
			data["last_failed_login_at"] = u.LastFailedLoginAt.UTC().Format(time.RFC3339)
		}
		if u.LoginLockedUntil != nil {
			data["login_locked_until"] = u.LoginLockedUntil.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": data})
	})

	// PUT /api/v1/system/users/{id}/login-lockout — backs UpdateLoginLockoutState.
	mux.HandleFunc("/api/v1/system/users/1/login-lockout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			FailedLoginAttempts int        `json:"failed_login_attempts"`
			LastFailedLoginAt   *time.Time `json:"last_failed_login_at"`
			LoginLockedUntil    *time.Time `json:"login_locked_until"`
			LoginLockoutCount   int        `json:"login_lockout_count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.user.FailedLoginAttempts = body.FailedLoginAttempts
		f.user.LastFailedLoginAt = body.LastFailedLoginAt
		f.user.LoginLockedUntil = body.LoginLockedUntil
		f.user.LoginLockoutCount = body.LoginLockoutCount
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"updated":true}}`)
	})

	// POST /api/v1/audit/events — backs LogAuditEvent, so UnlockUser's audit write
	// (EventAccountUnlocked) genuinely round-trips too, not just the counter reset.
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		var event models.AuditEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.events = append(f.events, event.EventType)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":true,"data":{"id":1}}`)
	})

	return httptest.NewServer(mux)
}

// newRemoteLockoutCoreAgainst builds a KeyorixCore backed by RemoteStorage — the
// backend a server runs when configured with storage.type: remote — pointed at a
// real (test) HTTP server, so recordFailedLogin/checkLockAndClearLoginFailures/
// clearLoginFailures/UnlockUser genuinely round-trip over HTTP rather than being
// stubbed out.
func newRemoteLockoutCoreAgainst(t *testing.T, baseURL string, policy LoginLockoutPolicy) *KeyorixCore {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: baseURL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: rs, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetLoginLockoutPolicy(policy)
	return c
}

// TestLockout_RemoteStorageGenuinelyPersistsAndLocks (#529) proves the fix: under
// storage.type: remote, recordFailedLogin's writes now genuinely land on the
// upstream server — the failed-attempt counter increments across calls and the
// account actually locks at the threshold, exactly matching LocalStorage's own
// behavior (TestLoginLockout_LocksAfterMaxAttempts) — instead of every write
// silently no-op'ing for the life of the process.
func TestLockout_RemoteStorageGenuinelyPersistsAndLocks(t *testing.T) {
	upstream := newFakeUpstreamLoginLockout(models.User{ID: 1, Username: "bob", AccountState: AccountActive, IsActive: true})
	srv := upstream.server(t)
	defer srv.Close()

	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	c := newRemoteLockoutCoreAgainst(t, srv.URL, policy)
	ctx := context.Background()
	user := &models.User{ID: 1, Username: "bob", AccountState: AccountActive, IsActive: true}

	out := captureLog(t, func() {
		c.recordFailedLogin(ctx, user)
	})
	assert.Empty(t, out, "the accounting write now genuinely succeeds — no more INERT operator warning")
	assert.Equal(t, 1, upstream.snapshot().FailedLoginAttempts,
		"#529: the failed-attempt counter must genuinely persist upstream, not silently no-op")
	assert.Nil(t, upstream.snapshot().LoginLockedUntil, "below the threshold, not yet locked")

	c.recordFailedLogin(ctx, user)
	assert.Equal(t, 2, upstream.snapshot().FailedLoginAttempts)

	// The 3rd failure trips the lock.
	c.recordFailedLogin(ctx, user)
	locked := upstream.snapshot()
	require.NotNil(t, locked.LoginLockedUntil,
		"#529: the account must genuinely lock upstream at MaxAttempts, matching LocalStorage's behavior")
	assert.Equal(t, 1, locked.LoginLockoutCount)
	assert.Equal(t, 0, locked.FailedLoginAttempts, "the window counter resets once the lock itself takes over")
}

// TestLockout_RemoteStorageGenuinelyClears (#529) proves
// checkLockAndClearLoginFailures/clearLoginFailures genuinely reset the upstream
// accounting after a successful login, instead of the reset silently no-op'ing.
func TestLockout_RemoteStorageGenuinelyClears(t *testing.T) {
	past := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC) // already-expired lock
	upstream := newFakeUpstreamLoginLockout(models.User{
		ID: 1, Username: "carol", AccountState: AccountActive, IsActive: true,
		FailedLoginAttempts: 2, LoginLockoutCount: 1, LoginLockedUntil: &past,
	})
	srv := upstream.server(t)
	defer srv.Close()

	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	c := newRemoteLockoutCoreAgainst(t, srv.URL, policy)
	ctx := context.Background()
	user := &models.User{ID: 1, Username: "carol", AccountState: AccountActive, IsActive: true, FailedLoginAttempts: 2, LoginLockoutCount: 1}

	out := captureLog(t, func() {
		err := c.checkLockAndClearLoginFailures(ctx, user)
		assert.NoError(t, err, "the (already-expired) lock must not block login")
	})
	assert.Empty(t, out, "clearing now genuinely succeeds — no more INERT operator warning")

	cleared := upstream.snapshot()
	assert.Zero(t, cleared.FailedLoginAttempts, "#529: the failure counters must genuinely reset upstream")
	assert.Zero(t, cleared.LoginLockoutCount)
	assert.Nil(t, cleared.LoginLockedUntil)
	assert.Zero(t, user.FailedLoginAttempts, "the caller's in-memory struct reflects the persisted clear")
}

// TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits (#529, closing #484's own
// follow-up gap) proves the admin UnlockUser action genuinely clears the upstream
// lockout state AND its audit event genuinely lands upstream too — not just that
// the call returns no error to the admin.
func TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits(t *testing.T) {
	future := time.Date(2026, 6, 12, 11, 0, 0, 0, time.UTC) // still-active lock
	upstream := newFakeUpstreamLoginLockout(models.User{
		ID: 1, Username: "dave", AccountState: AccountActive, IsActive: true,
		FailedLoginAttempts: 2, LoginLockoutCount: 1, LoginLockedUntil: &future,
	})
	srv := upstream.server(t)
	defer srv.Close()

	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	c := newRemoteLockoutCoreAgainst(t, srv.URL, policy)
	ctx := context.Background()

	out := captureLog(t, func() {
		err := c.UnlockUser(ctx, 99, 1)
		assert.NoError(t, err)
	})
	assert.Empty(t, out, "the unlock write now genuinely succeeds — no more INERT operator warning")

	unlocked := upstream.snapshot()
	assert.Zero(t, unlocked.FailedLoginAttempts, "#529: an admin unlock must genuinely clear the upstream lockout state")
	assert.Zero(t, unlocked.LoginLockoutCount)
	assert.Nil(t, unlocked.LoginLockedUntil, "the still-active lock must be genuinely lifted, not merely left to expire")

	assert.Contains(t, upstream.auditEventTypes(), EventAccountUnlocked,
		"the admin unlock must still be audited even though the write now succeeds")
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
