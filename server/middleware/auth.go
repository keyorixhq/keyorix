package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// UserContext represents the authenticated user context
type UserContext struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	userContextKey contextKey = "user"
)

// Authentication returns a middleware that validates JWT tokens and sets user context
func Authentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorizedResponse(w, "Missing authorization header")
				return
			}

			// Check for Bearer token format
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				unauthorizedResponse(w, "Invalid authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				unauthorizedResponse(w, "Missing token")
				return
			}

			// TODO: Validate JWT token and extract user information
			// For now, we'll use a mock implementation
			userCtx, err := validateToken(token)
			if err != nil {
				unauthorizedResponse(w, "Invalid or expired token")
				return
			}

			// Add user context to request
			ctx := context.WithValue(r.Context(), userContextKey, userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequirePermission returns a middleware that checks if the user has a specific permission
func RequirePermission(permission string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}

			// Check if user has the required permission
			hasPermission := false
			for _, perm := range userCtx.Permissions {
				if perm == permission {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				forbiddenResponse(w, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns a middleware that checks if the user has a specific role
func RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}

			// Check if user has the required role
			hasRole := false
			for _, userRole := range userCtx.Roles {
				if userRole == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				forbiddenResponse(w, "Insufficient role")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts the user context from the request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if userCtx, ok := ctx.Value(userContextKey).(*UserContext); ok {
		return userCtx
	}
	return nil
}

// validateToken validates a JWT token and returns user context
// TODO: Implement actual JWT validation
func validateToken(token string) (*UserContext, error) {
	// Mock implementation - replace with actual JWT validation
	if token == "valid-token" {
		return &UserContext{
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
		}, nil
	}

	// For development, allow a test token
	if token == "test-token" {
		return &UserContext{
			UserID:   2,
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []string{"viewer"},
			Permissions: []string{
				"secrets.read",
				"users.read",
			},
		}, nil
	}

	// Test token representing user id 2 (share recipient) in HTTP integration tests
	if token == "recipient-token" {
		return &UserContext{
			UserID:   2,
			Username: "user2",
			Email:    "user2@test.com",
			Roles:    []string{"user"},
			Permissions: []string{
				"secrets.read",
			},
		}, nil
	}

	// Test token for share owner scenarios (same user id as valid-token admin in seeded tests)
	if token == "owner-token" {
		return &UserContext{
			UserID:   1,
			Username: "owner",
			Email:    "owner@example.com",
			Roles:    []string{"admin"},
			Permissions: []string{
				"secrets.read", "secrets.write", "secrets.delete",
				"users.read", "users.write", "users.delete",
				"roles.read", "roles.write", "roles.assign",
				"audit.read", "system.read",
			},
		}, nil
	}

	return nil, http.ErrNotSupported
}

// unauthorizedResponse sends a 401 Unauthorized response
func unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"error":   "Unauthorized",
		"message": message,
		"code":    http.StatusUnauthorized,
	}

	_ = json.NewEncoder(w).Encode(response)
}

// forbiddenResponse sends a 403 Forbidden response
func forbiddenResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	response := map[string]interface{}{
		"error":   "Forbidden",
		"message": message,
		"code":    http.StatusForbidden,
	}

	_ = json.NewEncoder(w).Encode(response)
}

// GetUserContextKey returns the context key for user context (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}
