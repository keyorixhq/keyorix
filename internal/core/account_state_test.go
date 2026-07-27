package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAccountStateHelpers(t *testing.T) {
	assert.Equal(t, AccountActive, NormalizeAccountState(""))
	assert.Equal(t, AccountSuspended, NormalizeAccountState(AccountSuspended))

	assert.True(t, AccountRestricted(AccountPendingFirstLogin))
	assert.True(t, AccountRestricted(AccountPasswordResetRequired))
	assert.False(t, AccountRestricted(AccountActive))
	assert.False(t, AccountRestricted("")) // legacy → active

	assert.True(t, AccountLoginBlocked(AccountSuspended))
	assert.False(t, AccountLoginBlocked(AccountActive))

	// A restricted state clears to active on password change; others unchanged.
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(AccountPasswordResetRequired))
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(AccountPendingFirstLogin))
	assert.Equal(t, AccountSuspended, clearRestrictionOnPasswordChange(AccountSuspended))
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(""))
}

// TestIsValidAccountState proves #334's write-path validation: the empty string
// and every canonical ADR-025 value are valid, and nothing else is.
func TestIsValidAccountState(t *testing.T) {
	for _, s := range []string{"", AccountActive, AccountPendingFirstLogin, AccountPasswordResetRequired, AccountSuspended, AccountDeprovisioned} {
		assert.True(t, IsValidAccountState(s), "expected %q to be valid", s)
	}
	for _, s := range []string{"SUSPENDED", "suspend", "Active", "not-a-real-state", " "} {
		assert.False(t, IsValidAccountState(s), "expected %q to be invalid", s)
	}
}

// TestAccountState_UnrecognizedValueFailsClosed proves #334's defense-in-depth
// backstop: an unrecognized account_state value (e.g. one persisted before the
// write-path validation shipped) is treated as restricted — never as fully
// active/unrestricted — while still not being an outright login block, since a
// restricted session can self-heal via a password change.
func TestAccountState_UnrecognizedValueFailsClosed(t *testing.T) {
	garbage := "not-a-real-state"

	assert.True(t, AccountRestricted(garbage), "unrecognized state must fail closed to restricted")
	assert.False(t, AccountLoginBlocked(garbage), "unrecognized state must not hard-lock out login (no self-heal path)")

	// An unrecognized-but-restricted state still self-heals to active on the
	// next password change, exactly like the canonical restricted states.
	assert.Equal(t, AccountActive, clearRestrictionOnPasswordChange(garbage))

	// The canonical, previously-tested behaviors are unchanged by the new default.
	assert.True(t, AccountRestricted(AccountPendingFirstLogin))
	assert.True(t, AccountRestricted(AccountPasswordResetRequired))
	assert.False(t, AccountRestricted(AccountActive))
	assert.False(t, AccountRestricted(AccountSuspended))
	assert.False(t, AccountRestricted(AccountDeprovisioned))
	assert.False(t, AccountRestricted(""))

	assert.True(t, AccountLoginBlocked(AccountSuspended))
	assert.True(t, AccountLoginBlocked(AccountDeprovisioned))
	assert.False(t, AccountLoginBlocked(AccountActive))
	assert.False(t, AccountLoginBlocked(AccountPendingFirstLogin))
	assert.False(t, AccountLoginBlocked(AccountPasswordResetRequired))
	assert.False(t, AccountLoginBlocked(""))
}

func newAccountCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }, passwordPolicy: DefaultPasswordPolicy()}
}

func TestAdminAccountTransitions(t *testing.T) {
	cases := []struct {
		name      string
		call      func(c *KeyorixCore, ctx context.Context) error
		wantState string
		event     string
	}{
		{"suspend", func(c *KeyorixCore, ctx context.Context) error { return c.SuspendUser(ctx, 1, 2) }, AccountSuspended, "account.suspended"},
		{"reactivate", func(c *KeyorixCore, ctx context.Context) error { return c.ReactivateUser(ctx, 1, 2) }, AccountActive, "account.reactivated"},
		{"require reset", func(c *KeyorixCore, ctx context.Context) error { return c.RequirePasswordReset(ctx, 1, 2) }, AccountPasswordResetRequired, "account.password_reset_required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(MockStorage)
			c := newAccountCore(store)
			ctx := context.Background()
			store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, AccountState: AccountActive}, nil)
			store.On("SetAccountState", ctx, uint(2), tc.wantState, mock.Anything).Return(nil)
			store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
				return e.EventType == tc.event
			})).Return(nil)
			// Every state change evicts the user's cached session tokens from the auth cache.
			store.On("ListSessionTokenHashesForUser", ctx, uint(2)).Return([]string{}, nil)
			// Every state change also evicts PAT hashes for immediate cache invalidation
			// (#r125-H2: password_reset_required previously skipped PAT eviction).
			store.On("ListPersonalAccessTokensByUser", ctx, uint(2)).Return([]*models.PersonalAccessToken{}, nil)
			// A login-blocking transition (suspend) must purge the user's sessions AND PATs.
			if AccountLoginBlocked(tc.wantState) {
				store.On("DeleteSessionsForUserExcept", ctx, uint(2), uint(0)).Return(nil)
				store.On("RevokeAllPersonalAccessTokensForUser", ctx, uint(2)).Return([]string{}, nil)
			}

			require.NoError(t, tc.call(c, ctx))
			store.AssertExpectations(t)
			if !AccountLoginBlocked(tc.wantState) {
				store.AssertNotCalled(t, "DeleteSessionsForUserExcept", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestLogin_BlocksSuspended(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), bcrypt.DefaultCost)
	// A suspended account keeps IsActive=true (SuspendUser changes only account_state),
	// so the state-based gate — not the IsActive gate — is what refuses the login.
	store.On("GetUserByUsername", ctx, "bob").
		Return(&models.User{ID: 2, Username: "bob", PasswordHash: string(hash), IsActive: true, AccountState: AccountSuspended}, nil)

	_, _, err := c.Login(ctx, &LoginRequest{Username: "bob", Password: "Secret#Passw0rd!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A deactivated account (IsActive=false, e.g. admin deactivation via UpdateUser or a
// SCIM/IdP deactivation) must be refused login even with the correct password and an
// otherwise-active account_state — the state gate alone does not cover IsActive.
func TestLogin_BlocksDeactivated(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("Secret#Passw0rd!"), bcrypt.DefaultCost)
	store.On("GetUserByUsername", ctx, "bob").
		Return(&models.User{ID: 2, Username: "bob", PasswordHash: string(hash), IsActive: false, AccountState: AccountActive}, nil)

	_, _, err := c.Login(ctx, &LoginRequest{Username: "bob", Password: "Secret#Passw0rd!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A suspended or deactivated account must not authenticate via an existing,
// not-yet-expired session token (the suspend/deactivate revocation gap).
func TestValidateSessionToken_RejectsBlockedOrInactive(t *testing.T) {
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC) // after newAccountCore's fixed now
	cases := []struct {
		name string
		user *models.User
	}{
		{"suspended", &models.User{ID: 2, IsActive: true, AccountState: AccountSuspended}},
		{"inactive", &models.User{ID: 2, IsActive: false, AccountState: AccountActive}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := new(MockStorage)
			c := newAccountCore(store)
			ctx := context.Background()
			store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ExpiresAt: &future}, nil)
			store.On("GetUser", ctx, uint(2)).Return(tc.user, nil)

			_, _, err := c.ValidateSessionToken(ctx, "tok")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not active")
			store.AssertNotCalled(t, "GetUserRoles", mock.Anything, mock.Anything)
			// Must reject before stamping last-seen — a blocked/inactive account's
			// request is not "used" and must not refresh the sessions view (matching
			// ValidatePATToken's touch-after-gate ordering).
			store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// An impersonation session (target active) must be rejected once the IMPERSONATING
// admin is suspended/deactivated — the session is keyed to the target's user_id, so
// the target-state gate alone would let a revoked admin keep acting as the target.
func TestValidateSessionToken_RejectsWhenImpersonatorBlocked(t *testing.T) {
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	admin := uint(1)
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ImpersonatedBy: &admin, ExpiresAt: &future}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, IsActive: true, AccountState: AccountSuspended}, nil)

	_, _, err := c.ValidateSessionToken(ctx, "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "impersonating account is not active")
	store.AssertNotCalled(t, "TouchSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestValidateSessionToken_AllowsActive(t *testing.T) {
	future := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 2, ExpiresAt: &future}, nil)
	store.On("TouchSession", ctx, uint(7), mock.Anything, mock.Anything).Return(nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoles", ctx, uint(2)).Return([]*models.Role{{Name: "viewer"}}, nil)

	user, roles, err := c.ValidateSessionToken(ctx, "tok")
	require.NoError(t, err)
	assert.Equal(t, uint(2), user.ID)
	assert.Equal(t, []string{"viewer"}, roles)
}

func TestChangePassword_ClearsRestriction(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()
	oldHash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	user := &models.User{ID: 1, Username: "alice", PasswordHash: string(oldHash), AccountState: AccountPasswordResetRequired}

	store.On("GetUser", ctx, uint(1)).Return(user, nil)
	store.On("RecentPasswordHashes", ctx, uint(1), 5).Return([]string{}, nil)
	store.On("SetPasswordHash", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	store.On("SetAccountState", ctx, uint(1), AccountActive, mock.Anything).Return(nil) // restriction cleared
	store.On("AddPasswordHistory", ctx, uint(1), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	store.On("PrunePasswordHistory", ctx, uint(1), 5).Return(nil)
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 7, UserID: 1}, nil)
	store.On("ListSessionTokenHashesForUser", ctx, uint(1)).Return([]string{}, nil)
	store.On("DeleteSessionsForUserExcept", ctx, uint(1), uint(7)).Return(nil)
	store.On("RevokeAllPersonalAccessTokensForUser", mock.Anything, mock.Anything).Return(nil, nil)

	err := c.ChangePassword(ctx, 1, "oldpassword", "Brandnew#Passw0rd!", "tok")
	require.NoError(t, err)
	store.AssertExpectations(t)
}

// TestRequirePasswordReset_EvictsPATCache verifies that RequirePasswordReset evicts
// PAT token hashes from the auth cache, not only session hashes (#r125-H2). Without
// this eviction, a cached PAT request would bypass the password_reset_required
// restriction for up to validTokenTTL (30 s) — the cache fast-path returns the
// old, unrestricted identity without re-reading the DB.
func TestRequirePasswordReset_EvictsPATCache(t *testing.T) {
	store := new(MockStorage)
	c := newAccountCore(store)
	ctx := context.Background()

	const userID = uint(5)
	patHash := "sha256-pat-hash-abc"

	// LockUserForUpdate delegates to GetUser inside the mock.
	store.On("GetUser", ctx, userID).Return(&models.User{ID: userID, AccountState: AccountActive}, nil)
	store.On("ListSessionTokenHashesForUser", ctx, userID).Return([]string{}, nil)
	store.On("ListPersonalAccessTokensByUser", ctx, userID).Return([]*models.PersonalAccessToken{
		{ID: 1, UserID: userID, TokenHash: patHash, Revoked: false},
	}, nil)
	store.On("SetAccountState", ctx, userID, AccountPasswordResetRequired, mock.Anything).Return(nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "account.password_reset_required"
	})).Return(nil)

	var evicted []string
	c.SetTokenCacheInvalidator(func(h string) { evicted = append(evicted, h) })

	require.NoError(t, c.RequirePasswordReset(ctx, 1, userID))

	// The PAT hash must have been evicted so the next PAT request re-reads the DB
	// and observes the new password_reset_required restriction.
	assert.Contains(t, evicted, patHash, "RequirePasswordReset must evict PAT hashes from auth cache")
	store.AssertExpectations(t)
}
