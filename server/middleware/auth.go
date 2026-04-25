package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
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
	userContextKey        contextKey = "user"
	coreServiceContextKey contextKey = "coreService"
)

// Authentication returns a middleware that validates session tokens against the database.
func Authentication(coreService *core.KeyorixCore) func(next http.Handler) http.Handler {
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

			userCtx, err := validateToken(r.Context(), coreService, token)
			if err != nil {
				unauthorizedResponse(w, "Invalid or expired token")
				return
			}

			// Add user context and core service to request
			ctx := context.WithValue(r.Context(), userContextKey, userCtx)
			ctx = context.WithValue(ctx, coreServiceContextKey, coreService)
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

var adminPermissions = []string{
	"secrets.read", "secrets.write", "secrets.delete",
	"users.read", "users.write", "users.delete",
	"roles.read", "roles.write", "roles.assign",
	"audit.read", "system.read",
}

var readPermissions = []string{
	"secrets.read",
	"users.read",
}

// validateToken first checks the database for a real session, then falls back to
// hardcoded test tokens for backwards compatibility with integration tests.
func validateToken(ctx context.Context, coreService *core.KeyorixCore, token string) (*UserContext, error) {
	// Real DB lookup — try this before hardcoded tokens
	if coreService != nil {
		user, roleNames, err := coreService.ValidateSessionToken(ctx, token)
		if err == nil {
			perms := readPermissions
			for _, r := range roleNames {
				if r == "admin" {
					perms = adminPermissions
					break
				}
			}
			return &UserContext{
				UserID:      user.ID,
				Username:    user.Username,
				Email:       user.Email,
				Roles:       roleNames,
				Permissions: perms,
			}, nil
		}
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

// GetCoreServiceFromContext retrieves the core service from the request context.
func GetCoreServiceFromContext(ctx context.Context) *core.KeyorixCore {
	if cs, ok := ctx.Value(coreServiceContextKey).(*core.KeyorixCore); ok {
		return cs
	}
	return nil
}
