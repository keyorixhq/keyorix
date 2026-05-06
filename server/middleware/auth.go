package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sessionValidator is the subset of *core.KeyorixCore that the auth middleware
// needs. Defined here (not in core) so tests can supply a fake validator without
// constructing a full core service. *core.KeyorixCore satisfies this implicitly.
type sessionValidator interface {
	ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error)
}

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

	// TTL for valid token cache entries (session is trusted for this window).
	validTokenTTL = 30 * time.Second
	// TTL for negative cache entries (stale/invalid tokens — MCP storm fix).
	// Short enough that a legitimately re-issued token works after ~10s.
	invalidTokenTTL = 10 * time.Second
)

// tokenCacheEntry holds a cached auth result.
type tokenCacheEntry struct {
	userCtx   *UserContext // nil for negative entries
	expiresAt time.Time
}

// tokenCache is a process-wide cache keyed by SHA-256(token).
// Prevents repeated DB hits from stale MCP tokens after server restart.
var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]tokenCacheEntry{}
	lastPurge    = time.Now()
)

// tokenKey returns a safe cache key (SHA-256 hex of the raw token).
func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// cacheGet returns (entry, found). Caller must hold no lock — acquires internally.
func cacheGet(key string) (tokenCacheEntry, bool) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	e, ok := tokenCache[key]
	if !ok {
		return tokenCacheEntry{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(tokenCache, key)
		return tokenCacheEntry{}, false
	}
	return e, true
}

// cacheSet stores an entry. Caller must hold no lock.
func cacheSet(key string, entry tokenCacheEntry) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	tokenCache[key] = entry
	// Periodic O(n) purge — runs at most once per minute.
	if time.Since(lastPurge) > time.Minute {
		now := time.Now()
		for k, v := range tokenCache {
			if now.After(v.expiresAt) {
				delete(tokenCache, k)
			}
		}
		lastPurge = now
	}
}

// Authentication returns a middleware that validates session tokens against the database,
// with a short-circuit cache to absorb stale-token storms (e.g. MCP client retry bursts).
func Authentication(coreService *core.KeyorixCore) func(next http.Handler) http.Handler {
	return authenticationWithValidator(coreService, coreService)
}

// authenticationWithValidator is the test seam: it accepts a sessionValidator for
// validating tokens (so tests can inject a fake) and a separate *core.KeyorixCore
// to store in the request context for downstream handlers.
func authenticationWithValidator(validator sessionValidator, coreService *core.KeyorixCore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorizedResponse(w, "Missing authorization header")
				return
			}

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

			key := tokenKey(token)

			// Fast path: cache hit.
			if entry, ok := cacheGet(key); ok {
				if entry.userCtx == nil {
					// Negative cache — known bad token, skip DB entirely.
					unauthorizedResponse(w, "Invalid or expired token")
					return
				}
				ctx := context.WithValue(r.Context(), userContextKey, entry.userCtx)
				ctx = context.WithValue(ctx, coreServiceContextKey, coreService)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Slow path: DB lookup.
			userCtx, err := validateToken(r.Context(), validator, token)
			if err != nil {
				// Cache the negative result so subsequent retries skip the DB.
				cacheSet(key, tokenCacheEntry{userCtx: nil, expiresAt: time.Now().Add(invalidTokenTTL)})
				unauthorizedResponse(w, "Invalid or expired token")
				return
			}

			// Cache the positive result.
			cacheSet(key, tokenCacheEntry{userCtx: userCtx, expiresAt: time.Now().Add(validTokenTTL)})

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
			for _, perm := range userCtx.Permissions {
				if perm == permission {
					next.ServeHTTP(w, r)
					return
				}
			}
			forbiddenResponse(w, "Insufficient permissions")
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
			for _, userRole := range userCtx.Roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			forbiddenResponse(w, "Insufficient role")
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

// validateToken validates a session token via the supplied validator and returns
// the resolved UserContext.
func validateToken(ctx context.Context, validator sessionValidator, token string) (*UserContext, error) {
	if validator == nil {
		return nil, http.ErrNotSupported
	}
	user, roleNames, err := validator.ValidateSessionToken(ctx, token)
	if err != nil {
		return nil, err
	}
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

// unauthorizedResponse sends a 401 Unauthorized response
func unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Unauthorized", "message": message, "code": http.StatusUnauthorized,
	})
}

// forbiddenResponse sends a 403 Forbidden response
func forbiddenResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Forbidden", "message": message, "code": http.StatusForbidden,
	})
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

// InvalidateTokenCache removes a specific token from the auth cache.
// Call this on logout to ensure the token is rejected immediately.
func InvalidateTokenCache(token string) {
	key := tokenKey(token)
	tokenCacheMu.Lock()
	delete(tokenCache, key)
	tokenCacheMu.Unlock()
}
