// password_remote_test.go — regression coverage for #484: applyNewPassword (shared by
// self-service ChangePassword and the setup-token consume flow) must persist via the
// narrow SetPasswordHash/SetAccountState primitives, not the generic UpdateUser, so a
// backend that can never carry password_hash over the wire (RemoteStorage) hard-fails
// instead of reporting a false "success". Mirrors #454's own test style: a real
// RemoteStorage against an httptest server for the remote-storage case, and a real
// SQLite-backed LocalStorage for the "still works correctly" case.
package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newRemotePasswordCore builds a KeyorixCore backed by RemoteStorage against a real
// httptest server that only ever serves GET /api/v1/users/{id} (returning `user`
// unchanged) — and fails the test outright if anything ever reaches the server with a
// PUT, proving the #484 fix refuses the write BEFORE attempting the lossy wire
// round-trip that would otherwise silently drop password_hash (json:"-", never even
// serialized) and report a false success.
func newRemotePasswordCore(t *testing.T, user *models.User) *KeyorixCore {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected %s %s: a password change must hard-fail BEFORE any wire "+
				"round-trip, since password_hash can never be carried by it", r.Method, r.URL.Path)
		}
		apiOKUser(t, w, user)
	}))
	t.Cleanup(srv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)
	now := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: rs, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
}

// TestApplyNewPassword_HardFailsUnderRemoteStorage is the #484 regression: applyNewPassword
// — shared by self-service ChangePassword and the setup-token consume flow — must fail
// closed under storage.type: remote, never report success while the stored hash silently
// stays unchanged upstream. Calls applyNewPassword directly (as the audit's own scratch
// repro did), bypassing ChangePassword's own current-password re-verification: that check
// separately depends on GetUser returning a usable PasswordHash, which RemoteStorage can
// never do either (PasswordHash is also json:"-", so it can't survive that round-trip),
// an orthogonal pre-existing gap this fix does not need to touch.
func TestApplyNewPassword_HardFailsUnderRemoteStorage(t *testing.T) {
	user := &models.User{ID: 7, Username: "remote-bob", AccountState: AccountActive}
	c := newRemotePasswordCore(t, user)

	err := c.applyNewPassword(context.Background(), user, "Brandnew#Passw0rd!")
	require.Error(t, err, "a password change must hard-fail, not silently succeed, under remote storage")
	assert.ErrorIs(t, err, corestorage.ErrUnsupportedByBackend)
}

// TestApplyNewPassword_HardFailsUnderRemoteStorage_EvenWithRestrictedState proves the
// hard-fail also covers the case where the change would additionally need to clear a
// restricted account state (ADR-025): SetPasswordHash fails first, inside the same
// transaction, before SetAccountState is ever reached — no partial application either.
func TestApplyNewPassword_HardFailsUnderRemoteStorage_EvenWithRestrictedState(t *testing.T) {
	user := &models.User{ID: 8, Username: "remote-carol", AccountState: AccountPasswordResetRequired}
	c := newRemotePasswordCore(t, user)

	err := c.applyNewPassword(context.Background(), user, "Brandnew#Passw0rd!")
	require.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrUnsupportedByBackend)
}

// TestChangePassword_LocalStoragePersistsHashAndClearsRestriction proves LocalStorage
// still performs the real column update via SetPasswordHash/SetAccountState — the #484
// fix must not regress the working (non-remote) case.
func TestChangePassword_LocalStoragePersistsHashAndClearsRestriction(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.PasswordHistory{}))
	oldHash, err := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "carol", PasswordHash: string(oldHash), AccountState: AccountPasswordResetRequired,
	}).Error)

	c := &KeyorixCore{
		storage:        store.NewLocalStorage(db),
		now:            func() time.Time { return time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC) },
		passwordPolicy: DefaultPasswordPolicy(),
	}

	const newPw = "Brandnew#Passw0rd!"
	require.NoError(t, c.ChangePassword(context.Background(), 1, "oldpassword", newPw, ""))

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(newPw)),
		"the new hash must actually be persisted, not silently dropped")
	assert.Equal(t, AccountActive, u.AccountState, "restricted state must clear to active")
}
