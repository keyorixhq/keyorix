package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	validToken = "valid-token"
	testToken  = "test-token"
)

const wrongKey contextKey = "wrong-key"

// fakeValidator is a test double for sessionValidator. It returns a fixed
// admin user for validToken, a viewer user for testToken, and an error for
// anything else.
type fakeValidator struct{}

func (fakeValidator) ValidateSessionToken(_ context.Context, token string) (*models.User, []string, error) {
	switch token {
	case validToken:
		return &models.User{
			ID:       1,
			Username: "admin",
			Email:    "admin@example.com",
		}, []string{"admin", "user"}, nil
	case testToken:
		return &models.User{
			ID:       2,
			Username: "testuser",
			Email:    "test@example.com",
		}, []string{"viewer"}, nil
	default:
		return nil, nil, fmt.Errorf("session not found")
	}
}

// ValidatePATToken accepts a single fixed PAT and resolves it to a user, mirroring
// the shape of ValidateSessionToken so the prefix-routing in validateToken can be
// exercised. Anything else is rejected.
func (fakeValidator) ValidatePATToken(_ context.Context, token string) (*models.User, []string, *core.PATRestriction, error) {
	if token == "kx_pat_validtoken" {
		return &models.User{
			ID:       3,
			Username: "patuser",
			Email:    "pat@example.com",
		}, []string{"system_viewer"}, nil, nil
	}
	if token == "kx_pat_scopedtoken" {
		// A least-privilege token confined to secrets.read in project 5 (ADR-042).
		return &models.User{ID: 3, Username: "patuser", Email: "pat@example.com"},
			[]string{"system_viewer"},
			&core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: 5},
			nil
	}
	if token == "kx_pat_cidrtoken" {
		// A token restricted to the 10.0.0.0/8 network.
		return &models.User{ID: 3, Username: "patuser", Email: "pat@example.com"},
			[]string{"system_viewer"},
			&core.PATRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}},
			nil
	}
	return nil, nil, nil, fmt.Errorf("invalid token")
}

func (fakeValidator) ValidateMachineToken(_ context.Context, token string) (*models.MachineIdentity, []string, *core.MachineTokenRestriction, error) {
	if token == "kx_machine_validtoken" {
		return &models.MachineIdentity{
			ID:    9,
			Name:  "ci-bot",
			State: "active",
		}, []string{"project_viewer"}, nil, nil
	}
	return nil, nil, nil, fmt.Errorf("invalid token")
}

func (fakeValidator) OIDCEnabled() bool { return true }

func (fakeValidator) ValidateOIDCToken(_ context.Context, token string) (*models.MachineIdentity, []string, error) {
	// A three-segment dotted token whose middle segment marks it valid.
	if token == "header.valid.sig" {
		return &models.MachineIdentity{ID: 11, Name: "k8s-sa", State: "active"}, []string{"project_viewer"}, nil
	}
	return nil, nil, fmt.Errorf("invalid token")
}

// newTestAuthMiddleware builds the Authentication middleware with the fake
// validator. The coreService passed to authenticationWithValidator is nil here
// because none of these tests exercise downstream handlers that pull the core
// service out of context.
func newTestAuthMiddleware() func(next http.Handler) http.Handler {
	return authenticationWithValidator(fakeValidator{}, nil)
}

func TestAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectUserCtx  bool
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer valid-token",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "valid test token",
			authHeader:     "Bearer test-token",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			// kx_pat_ prefix routes to ValidatePATToken and resolves to a user,
			// producing the same UserContext shape as a session.
			name:           "valid personal access token",
			authHeader:     "Bearer kx_pat_validtoken",
			expectedStatus: http.StatusOK,
			expectUserCtx:  true,
		},
		{
			name:           "invalid personal access token",
			authHeader:     "Bearer kx_pat_bogus",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "malformed authorization header",
			authHeader:     "InvalidFormat token",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "bearer without token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
		{
			name:           "only bearer",
			authHeader:     "Bearer",
			expectedStatus: http.StatusUnauthorized,
			expectUserCtx:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that checks for user context
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userCtx := GetUserFromContext(r.Context())
				if tt.expectUserCtx {
					assert.NotNil(t, userCtx)
					assert.NotEmpty(t, userCtx.Username)
					assert.NotEmpty(t, userCtx.Email)
				} else {
					assert.Nil(t, userCtx)
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with authentication middleware
			authMiddleware := newTestAuthMiddleware()
			handler := authMiddleware(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRequireRole(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		role           string
		expectedStatus int
	}{
		{
			name:           "admin has admin role",
			token:          validToken,
			role:           "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin has user role",
			token:          validToken,
			role:           "user",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user has viewer role",
			token:          testToken,
			role:           "viewer",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user lacks admin role",
			token:          testToken,
			role:           "admin",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "nonexistent role",
			token:          validToken,
			role:           "nonexistent",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create user context based on token
			var userCtx *UserContext
			switch tt.token {
			case validToken:
				userCtx = &UserContext{
					UserID:   1,
					Username: "admin",
					Email:    "admin@example.com",
					Roles:    []string{"admin", "user"},
				}
			case testToken:
				userCtx = &UserContext{
					UserID:   2,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"viewer"},
				}
			}

			// Wrap with role middleware
			roleMiddleware := RequireRole(tt.role)
			handler := roleMiddleware(testHandler)

			// Create request with user context
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if userCtx != nil {
				ctx := context.WithValue(req.Context(), userContextKey, userCtx)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(w, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// A PAT carrying a least-privilege restriction (ADR-042) must not satisfy a role
// gate, even when its owner holds the role — RequireRole does not funnel through
// core.Authorize, so the restriction is enforced here directly (fail-closed).
func TestRequireRole_DeniesScopedPAT(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireRole("admin")(testHandler)

	t.Run("scoped PAT on an admin owner is forbidden", func(t *testing.T) {
		userCtx := &UserContext{
			UserID:         1,
			Username:       "admin",
			Roles:          []string{"admin", "user"},
			PATRestriction: &core.PATRestriction{Permissions: []string{"secrets.read"}},
		}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("same owner via a full session still passes", func(t *testing.T) {
		userCtx := &UserContext{UserID: 1, Username: "admin", Roles: []string{"admin", "user"}}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestRequireRole_DeniesMachinePrincipal reproduces the exact #308 landmine
// scenario: a machine identity holds "deployer" only via a grant scoped to
// Project A (10), but store.GetMachineRoles is intentionally unscoped and
// flattens that grant into a bare role name with no project attached —
// precisely what ValidateMachineToken/machineUserContext feed into
// userCtx.Roles for every machine-token-authenticated request. If RequireRole
// were ever wired onto an authorization-gating route, an unscoped name match
// against that role list would wrongly authorize the same machine identity on
// a request for a DIFFERENT project (B, 99) that its grant was never scoped
// to — silently bypassing project scoping entirely for machine principals.
//
// Before the #308 fix, RequireRole only checked the role name against
// userCtx.Roles and had no machine-principal guard, so this exact request
// would have incorrectly succeeded (StatusOK). After the fix, RequireRole
// unconditionally refuses to gate on any machine principal, so it is
// rejected — regardless of which project the route targets — closing the
// landmine at the consumer rather than depending on GetMachineRoles (or any
// other future unscoped data source) never being wired in.
func TestRequireRole_DeniesMachinePrincipal(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireRole("deployer")(testHandler)

	// Mirrors machineUserContext(m, roleNames) exactly as validateToken builds
	// it for a machine-token request: roleNames is store.GetMachineRoles's
	// unscoped output ("deployer" appears with no indication it was granted
	// only at project A/10) for a machine whose real grant is scoped to
	// project A alone.
	machineID := uint(42)
	userCtx := machineUserContext(
		&models.MachineIdentity{ID: machineID, Name: "ci-deployer"},
		[]string{"deployer"}, // GetMachineRoles' unscoped flattening of a project-A-only grant
		nil,
	)
	require.NotNil(t, userCtx.MachineIdentityID)
	require.Equal(t, machineID, *userCtx.MachineIdentityID)

	// The request targets project B (99) — a project the machine's grant was
	// never scoped to.
	req := httptest.NewRequest(http.MethodGet, "/projects/99/deploy", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "a machine principal must never satisfy RequireRole's unscoped name match (#308)")
}

func TestGetUserFromContext(t *testing.T) {
	tests := []struct {
		name         string
		setupCtx     func() context.Context
		expectUser   bool
		expectedID   uint
		expectedName string
	}{
		{
			name: "valid user context",
			setupCtx: func() context.Context {
				userCtx := &UserContext{
					UserID:   123,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"user"},
				}
				return context.WithValue(context.Background(), userContextKey, userCtx)
			},
			expectUser:   true,
			expectedID:   123,
			expectedName: "testuser",
		},
		{
			name: "empty context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectUser: false,
		},
		{
			name: "wrong context key",
			setupCtx: func() context.Context {
				userCtx := &UserContext{
					UserID:   123,
					Username: "testuser",
				}
				return context.WithValue(context.Background(), wrongKey, userCtx)
			},
			expectUser: false,
		},
		{
			name: "wrong context value type",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), userContextKey, "not-a-user-context")
			},
			expectUser: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			userCtx := GetUserFromContext(ctx)

			if tt.expectUser {
				require.NotNil(t, userCtx)
				assert.Equal(t, tt.expectedID, userCtx.UserID)
				assert.Equal(t, tt.expectedName, userCtx.Username)
			} else {
				assert.Nil(t, userCtx)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		expectError  bool
		expectedUser *UserContext
	}{
		{
			name:        "valid admin token",
			token:       validToken,
			expectError: false,
			expectedUser: &UserContext{
				UserID:   1,
				Username: "admin",
				Email:    "admin@example.com",
				Roles:    []string{"admin", "user"},
			},
		},
		{
			name:        "valid test token",
			token:       testToken,
			expectError: false,
			expectedUser: &UserContext{
				UserID:   2,
				Username: "testuser",
				Email:    "test@example.com",
				Roles:    []string{"viewer"},
			},
		},
		{
			name:        "invalid token",
			token:       "invalid-token",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx, err := validateToken(context.Background(), fakeValidator{}, tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, userCtx)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, userCtx)
				assert.Equal(t, tt.expectedUser.UserID, userCtx.UserID)
				assert.Equal(t, tt.expectedUser.Username, userCtx.Username)
				assert.Equal(t, tt.expectedUser.Email, userCtx.Email)
				assert.Equal(t, tt.expectedUser.Roles, userCtx.Roles)
			}
		})
	}
}

// TestValidateToken_PATRestriction asserts the ADR-042 least-privilege wiring:
// a scoped PAT surfaces its restriction on the UserContext, an unrestricted PAT
// and a session carry none, and buildRequestContext propagates the restriction so
// core.Authorize can enforce it downstream.
func TestValidateToken_PATRestriction(t *testing.T) {
	t.Run("scoped PAT carries its restriction and propagates to context", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "kx_pat_scopedtoken")
		require.NoError(t, err)
		require.NotNil(t, userCtx.PATRestriction)
		assert.Equal(t, []string{"secrets.read"}, userCtx.PATRestriction.Permissions)
		assert.Equal(t, uint(5), userCtx.PATRestriction.ProjectID)
		assert.False(t, userCtx.SessionAuth, "a PAT is not an interactive session")

		// The restriction filters as expected: the listed permission within the
		// token's project passes; a different permission or project is denied.
		assert.True(t, userCtx.PATRestriction.Allows("secrets.read", core.Scope{ProjectID: 5}))
		assert.False(t, userCtx.PATRestriction.Allows("secrets.write", core.Scope{ProjectID: 5}))
		assert.False(t, userCtx.PATRestriction.Allows("secrets.read", core.Scope{ProjectID: 6}))

		// buildRequestContext must not panic and must return a context carrying the
		// identity, so downstream core.Authorize reads the restriction off ctx.
		ctx := buildRequestContext(context.Background(), userCtx, nil)
		require.NotNil(t, ctx)
		assert.Equal(t, userCtx, GetUserFromContext(ctx))
	})

	t.Run("unrestricted PAT carries no restriction", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "kx_pat_validtoken")
		require.NoError(t, err)
		assert.Nil(t, userCtx.PATRestriction)
	})

	t.Run("session token carries no restriction", func(t *testing.T) {
		userCtx, err := validateToken(context.Background(), fakeValidator{}, "valid-token")
		require.NoError(t, err)
		assert.Nil(t, userCtx.PATRestriction)
		assert.True(t, userCtx.SessionAuth)
	})
}

// Benchmark tests
func BenchmarkAuthentication(b *testing.B) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authMiddleware := newTestAuthMiddleware()
	handler := authMiddleware(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Test concurrent access
func TestAuthenticationConcurrency(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userCtx := GetUserFromContext(r.Context())
		assert.NotNil(t, userCtx)
		w.WriteHeader(http.StatusOK)
	})

	authMiddleware := newTestAuthMiddleware()
	handler := authMiddleware(testHandler)

	const numGoroutines = 100
	results := make(chan int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer valid-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	successCount := 0
	for i := 0; i < numGoroutines; i++ {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}

	assert.Equal(t, numGoroutines, successCount)
}

// A PAT with a CIDR allowlist is honored per-request: accepted from an in-range source IP
// and denied (403) from outside — and the denial holds on the cached fast path too.
func TestAuthentication_PATNetworkAllowlist(t *testing.T) {
	mw := newTestAuthMiddleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer kx_pat_cidrtoken")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusOK, serve("10.1.2.3:5555"), "in-range source IP is allowed")
	// Second request caches the (valid) identity but must still be denied from off-network.
	assert.Equal(t, http.StatusForbidden, serve("203.0.113.9:5555"), "off-network source IP is forbidden")
	// And an in-range request after the cached deny still passes (per-request evaluation).
	assert.Equal(t, http.StatusOK, serve("10.9.9.9:443"), "in-range again after a deny")
}

// #146: a PAT's CIDR allowlist narrowed AFTER the first request (which cached the
// identity) must be enforced on the very next request — a cache HIT must not keep
// permitting a source IP the allowlist no longer allows, even within validTokenTTL.
func TestAuthentication_PATNetworkAllowlist_RefreshesOnCacheHit(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.PersonalAccessToken{}))
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "patuser", Email: "pat@example.com", IsActive: true}).Error)

	const raw = "kx_pat_cidrtoken"
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	cidrsJSON := `["10.0.0.0/8"]`
	pat := &models.PersonalAccessToken{ID: 1, UserID: 3, Name: "ci", TokenHash: hash, AllowedCIDRs: cidrsJSON}
	require.NoError(t, db.Create(pat).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	mw := authenticationWithValidator(fakeValidator{}, coreService)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	serve := func(remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	// First request (slow path, via fakeValidator): in-range, cached.
	require.Equal(t, http.StatusOK, serve("10.1.2.3:5555"))

	// An admin narrows the allowlist directly in storage — simulating a live
	// mid-incident restriction change on the SAME token the cache already holds.
	pat.AllowedCIDRs = `["192.0.2.0/24"]`
	require.NoError(t, db.Save(pat).Error)

	// The SAME source IP that was allowed a moment ago must now be denied — on the
	// cache-HIT path, not after the 30s TTL expires.
	assert.Equal(t, http.StatusForbidden, serve("10.1.2.3:5555"),
		"a narrowed allowlist must take effect on the very next request, not after the cache TTL")
	// And the newly-allowed network is now honored, also on a cache hit.
	assert.Equal(t, http.StatusOK, serve("192.0.2.7:5555"))
}

// A token revoked WHILE a slow-path validation was in flight must not be resurrected by
// that validation's positive cache write (the revocation-resurrection race).
func TestCacheSetValidated_DropsResurrectionAfterRevoke(t *testing.T) {
	key := tokenKey("race-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	tokenCacheMu.Unlock()

	validatedAt := time.Now()        // slow path began (before its DB read)
	time.Sleep(2 * time.Millisecond) //
	InvalidateTokenCacheByHash(key)  // token revoked during validation
	// The in-flight positive write must be refused (revoke is newer than validatedAt).
	cacheSetValidated(key, &UserContext{UserID: 1}, validatedAt, time.Now().Add(validTokenTTL))

	entry, ok := cacheGet(key)
	if !ok {
		return // tombstone may have already expired in CI; the key point is no positive entry
	}
	if entry.userCtx != nil {
		t.Error("a token revoked mid-validation must NOT be resurrected as a positive cache entry")
	}
}

// A positive write with no intervening revoke is cached normally.
func TestCacheSetValidated_CachesWhenNotRevoked(t *testing.T) {
	key := tokenKey("ok-token")
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	tokenCacheMu.Unlock()

	cacheSetValidated(key, &UserContext{UserID: 7}, time.Now(), time.Now().Add(validTokenTTL))
	entry, ok := cacheGet(key)
	if !ok || entry.userCtx == nil || entry.userCtx.UserID != 7 {
		t.Errorf("a non-revoked validation must be cached; got ok=%v entry=%+v", ok, entry)
	}
}

// pruneLocked hard-caps the cache so a flood of distinct tokens can't grow it unbounded.
func TestPruneLocked_EnforcesSizeCap(t *testing.T) {
	// Clear the shared cache before and after so the bulk insert doesn't bleed into other
	// tests that share the process-wide map.
	t.Cleanup(func() {
		tokenCacheMu.Lock()
		for k := range tokenCache {
			delete(tokenCache, k)
		}
		tokenCacheMu.Unlock()
	})
	tokenCacheMu.Lock()
	for k := range tokenCache {
		delete(tokenCache, k)
	}
	far := time.Now().Add(time.Hour)
	for i := 0; i < maxTokenCacheEntries+1000; i++ {
		tokenCache[tokenKey(string(rune(i))+"-x-"+time.Now().String()+string(rune(i)))] = tokenCacheEntry{expiresAt: far}
	}
	pruneLocked()
	n := len(tokenCache)
	tokenCacheMu.Unlock()
	if n > maxTokenCacheEntries {
		t.Errorf("cache size %d exceeds cap %d after prune", n, maxTokenCacheEntries)
	}
}
