package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
func (fakeValidator) ValidatePATToken(_ context.Context, token string) (*models.User, []string, error) {
	if token == "kx_pat_validtoken" {
		return &models.User{
			ID:       3,
			Username: "patuser",
			Email:    "pat@example.com",
		}, []string{"system_viewer"}, nil
	}
	return nil, nil, fmt.Errorf("invalid token")
}

func (fakeValidator) ValidateMachineToken(_ context.Context, token string) (*models.MachineIdentity, []string, error) {
	if token == "kx_machine_validtoken" {
		return &models.MachineIdentity{
			ID:    9,
			Name:  "ci-bot",
			State: "active",
		}, []string{"project_viewer"}, nil
	}
	return nil, nil, fmt.Errorf("invalid token")
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
