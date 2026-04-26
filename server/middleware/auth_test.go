package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	validToken = "valid-token"
	testToken  = "test-token"
)

const wrongKey contextKey = "wrong-key"

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
					assert.NotEmpty(t, userCtx.Permissions)
				} else {
					assert.Nil(t, userCtx)
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with authentication middleware
			authMiddleware := Authentication(nil)
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

func TestRequirePermission(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		permission     string
		expectedStatus int
	}{
		{
			name:           "admin has secrets.read permission",
			token:          validToken,
			permission:     "secrets.read",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin has secrets.write permission",
			token:          validToken,
			permission:     "secrets.write",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "admin has secrets.delete permission",
			token:          validToken,
			permission:     "secrets.delete",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user has secrets.read permission",
			token:          testToken,
			permission:     "secrets.read",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user lacks secrets.write permission",
			token:          testToken,
			permission:     "secrets.write",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "test user lacks secrets.delete permission",
			token:          testToken,
			permission:     "secrets.delete",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "admin has system.read permission",
			token:          validToken,
			permission:     "system.read",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "test user lacks system.read permission",
			token:          testToken,
			permission:     "system.read",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "nonexistent permission",
			token:          validToken,
			permission:     "nonexistent.permission",
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
					Permissions: []string{
						"secrets.read", "secrets.write", "secrets.delete",
						"users.read", "users.write", "users.delete",
						"roles.read", "roles.write", "roles.assign",
						"audit.read", "system.read",
					},
				}
			case testToken:
				userCtx = &UserContext{
					UserID:   2,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"viewer"},
					Permissions: []string{
						"secrets.read",
						"users.read",
					},
				}
			}

			// Wrap with permission middleware
			permissionMiddleware := RequirePermission(tt.permission)
			handler := permissionMiddleware(testHandler)

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
					Permissions: []string{
						"secrets.read", "secrets.write", "secrets.delete",
						"users.read", "users.write", "users.delete",
						"roles.read", "roles.write", "roles.assign",
						"audit.read", "system.read",
					},
				}
			case testToken:
				userCtx = &UserContext{
					UserID:   2,
					Username: "testuser",
					Email:    "test@example.com",
					Roles:    []string{"viewer"},
					Permissions: []string{
						"secrets.read",
						"users.read",
					},
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
					UserID:      123,
					Username:    "testuser",
					Email:       "test@example.com",
					Roles:       []string{"user"},
					Permissions: []string{"secrets.read"},
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
				Permissions: []string{
					"secrets.read", "secrets.write", "secrets.delete",
					"users.read", "users.write", "users.delete",
					"roles.read", "roles.write", "roles.assign",
					"audit.read", "system.read",
				},
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
				Permissions: []string{
					"secrets.read",
					"users.read",
				},
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
			userCtx, err := validateToken(context.Background(), nil, tt.token)

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
				assert.Equal(t, tt.expectedUser.Permissions, userCtx.Permissions)
			}
		})
	}
}

// Test middleware chaining
func TestMiddlewareChaining(t *testing.T) {
	// Chain authentication and permission middleware
	authMiddleware := Authentication(nil)
	permissionMiddleware := RequirePermission("secrets.read")

	t.Run("valid admin token", func(t *testing.T) {
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			assert.NotNil(t, userCtx)
			assert.Equal(t, "admin", userCtx.Username)
			w.WriteHeader(http.StatusOK)
		})

		handler := authMiddleware(permissionMiddleware(testHandler))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("valid test token with permission", func(t *testing.T) {
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			assert.NotNil(t, userCtx)
			assert.Equal(t, "testuser", userCtx.Username)
			w.WriteHeader(http.StatusOK)
		})

		handler := authMiddleware(permissionMiddleware(testHandler))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token") // test-token has secrets.read
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code) // test-token has secrets.read permission
	})

	t.Run("invalid token", func(t *testing.T) {
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called for invalid token")
		})

		handler := authMiddleware(permissionMiddleware(testHandler))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// Benchmark tests
func BenchmarkAuthentication(b *testing.B) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authMiddleware := Authentication(nil)
	handler := authMiddleware(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkRequirePermission(b *testing.B) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	permissionMiddleware := RequirePermission("secrets.read")
	handler := permissionMiddleware(testHandler)

	userCtx := &UserContext{
		UserID:      1,
		Username:    "admin",
		Permissions: []string{"secrets.read", "secrets.write"},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), userContextKey, userCtx)
	req = req.WithContext(ctx)

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

	authMiddleware := Authentication(nil)
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
