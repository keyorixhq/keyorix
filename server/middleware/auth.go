package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sessionValidator is the subset of *core.KeyorixCore that the auth middleware
// needs. Defined here (not in core) so tests can supply a fake validator without
// constructing a full core service. *core.KeyorixCore satisfies this implicitly.
//
// Two token kinds resolve to an identical UserContext: opaque session tokens and
// personal access tokens (PATs, prefixed patTokenPrefix). validateToken routes by
// prefix; either path produces the same identity, so the token cache and all
// downstream per-scope authorization work unchanged.
type sessionValidator interface {
	ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error)
	ValidatePATToken(ctx context.Context, token string) (*models.User, []string, error)
	ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, error)
}

// patTokenPrefix marks a personal access token (kept in sync with core.patPrefix).
const patTokenPrefix = "kx_pat_"
const machineTokenPrefix = "kx_machine_"

// UserContext represents the authenticated user context. It carries identity
// only — authorization is resolved per-request against the target scope by
// core.Authorize, not from a precomputed permission list.
type UserContext struct {
	UserID   uint     `json:"user_id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	// ImpersonatedBy is the initiating admin's ID when this is an impersonation
	// session (nil otherwise). Cached with the rest of the identity, so a single
	// per-token lookup decides it. Used to tag downstream audit events.
	ImpersonatedBy *uint `json:"impersonated_by,omitempty"`
	// AccountState is the ADR-025 lifecycle state; Restricted is true when the
	// account must change its password before using non-allowlisted endpoints.
	AccountState string `json:"account_state,omitempty"`
	Restricted   bool   `json:"-"`
	// MachineIdentityID is set (and UserID is 0) when the request authenticated
	// with a machine token (ADR-030). ActorType is "machine_identity" for such
	// requests and "user" otherwise.
	MachineIdentityID *uint  `json:"machine_identity_id,omitempty"`
	ActorType         string `json:"actor_type,omitempty"`
}

// ActorKind returns the principal's actor type ("user" or "machine_identity"),
// defaulting to user for legacy/empty contexts.
func (u *UserContext) ActorKind() string {
	if u.ActorType == core.ActorTypeMachine {
		return core.ActorTypeMachine
	}
	return core.ActorTypeUser
}

// PrincipalID returns the id to authorize against: the machine identity id for a
// machine request, otherwise the user id.
func (u *UserContext) PrincipalID() uint {
	if u.MachineIdentityID != nil {
		return *u.MachineIdentityID
	}
	return u.UserID
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
				next.ServeHTTP(w, r.WithContext(buildRequestContext(r.Context(), entry.userCtx, coreService)))
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

			// Resolve impersonation once, on the slow path, so it is cached with
			// the identity. PATs and machine tokens are never impersonation
			// sessions (prefix check).
			if coreService != nil && !strings.HasPrefix(token, patTokenPrefix) && !strings.HasPrefix(token, machineTokenPrefix) {
				userCtx.ImpersonatedBy = coreService.SessionImpersonator(r.Context(), token)
			}

			// Cache the positive result.
			cacheSet(key, tokenCacheEntry{userCtx: userCtx, expiresAt: time.Now().Add(validTokenTTL)})

			next.ServeHTTP(w, r.WithContext(buildRequestContext(r.Context(), userCtx, coreService)))
		})
	}
}

// errInvalidTarget / errTargetNotFound let scope resolvers signal whether a bad
// target should surface as 400 (unparseable) or 404 (no such resource).
var (
	errInvalidTarget  = errors.New("invalid target")
	errTargetNotFound = errors.New("target not found")
)

// ScopeResolver derives the project/environment a request acts on. It may load
// the target resource (e.g. a secret) via the core service to find its scope.
type ScopeResolver func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error)

// RequireScopedPermission returns middleware that authorizes the request: it
// resolves the target scope, then asks core.Authorize whether the user holds
// permission there. Denials are 403, an unparseable target is 400, and a
// missing target resource is 404.
func RequireScopedPermission(permission string, resolve ScopeResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}
			cs := GetCoreServiceFromContext(r.Context())
			if cs == nil {
				forbiddenResponse(w, "Authorization unavailable")
				return
			}
			scope, err := resolve(r, cs)
			if err != nil {
				if errors.Is(err, errTargetNotFound) {
					// Reveal "not found" only to callers who hold the permission
					// globally; otherwise deny without confirming the resource
					// exists (avoids existence enumeration by unprivileged users).
					if ok, aerr := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, core.Scope{}); aerr == nil && ok {
						notFoundResponse(w, "Resource not found")
					} else {
						forbiddenResponse(w, "Insufficient permissions")
					}
					return
				}
				badRequestResponse(w, "Invalid target")
				return
			}
			allowed, err := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, scope)
			if err != nil || !allowed {
				forbiddenResponse(w, "Insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission enforces a permission at global scope. Use it for
// admin-area routes (users, roles, audit, system) that are not tied to a
// particular project/environment.
func RequirePermission(permission string) func(next http.Handler) http.Handler {
	return RequireScopedPermission(permission, ScopeGlobal)
}

// restrictedAllowedSuffixes are the only endpoints a restricted (must-change-
// password) session may reach, beyond logout (registered at the root router).
var restrictedAllowedSuffixes = []string{
	"/auth/change-password",
	"/auth/profile",
}

// EnforceAccountRestriction blocks a restricted account (ADR-025
// pending_first_login / password_reset_required) from every endpoint except the
// password-change allowlist, returning 403 with a PasswordChangeRequired code so
// the client redirects to change-password. Applied inside the authenticated API
// group, after Authentication has populated the user context.
func EnforceAccountRestriction(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userCtx := GetUserFromContext(r.Context())
		if userCtx == nil || !userCtx.Restricted {
			next.ServeHTTP(w, r)
			return
		}
		for _, suffix := range restrictedAllowedSuffixes {
			if strings.HasSuffix(r.URL.Path, suffix) {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "PasswordChangeRequired",
			"message": "You must change your password before continuing.",
			"code":    http.StatusForbidden,
		})
	})
}

// ScopeGlobal always resolves to the global scope.
func ScopeGlobal(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
	return core.Scope{}, nil
}

// ScopeFromQuery reads optional project_id/environment_id query params (0 when
// absent). Used by list endpoints where the client narrows by scope.
func ScopeFromQuery(r *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
	return core.Scope{
		ProjectID:     scopeQueryUint(r, "project_id"),
		EnvironmentID: scopeQueryUint(r, "environment_id"),
	}, nil
}

// ScopeFromProjectParam treats the named path param as a project ID.
func ScopeFromProjectParam(param string) ScopeResolver {
	return func(r *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		return core.Scope{ProjectID: id}, nil
	}
}

// ScopeFromEnvParam treats the named path param as an environment ID and loads
// its owning project.
func ScopeFromEnvParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		env, err := cs.Storage().GetEnvironment(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: env.ProjectID, EnvironmentID: id}, nil
	}
}

// ScopeFromSecretParam treats the named path param as a secret ID and resolves
// the secret's project/environment. Uses the raw storage fetch (no read-count
// side effects).
func ScopeFromSecretParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		secret, err := cs.Storage().GetSecret(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
	}
}

// ScopeFromShareParam treats the named path param as a share ID and resolves the
// scope of the shared secret.
func ScopeFromShareParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		share, err := cs.Storage().GetShareRecord(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		secret, err := cs.Storage().GetSecret(r.Context(), share.SecretID)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
	}
}

// ScopeFromRotationPolicyParam treats the named path param as a rotation policy
// ID and resolves the policy's project/environment scope.
func ScopeFromRotationPolicyParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		policy, err := cs.Storage().GetRotationPolicy(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{
			ProjectID:     derefUint(policy.ProjectID),
			EnvironmentID: derefUint(policy.EnvironmentID),
		}, nil
	}
}

func scopePathUint(r *http.Request, param string) (uint, error) {
	v, err := strconv.ParseUint(chi.URLParam(r, param), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(v), nil
}

func scopeQueryUint(r *http.Request, key string) uint {
	if v, err := strconv.ParseUint(r.URL.Query().Get(key), 10, 32); err == nil {
		return uint(v)
	}
	return 0
}

func derefUint(p *uint) uint {
	if p == nil {
		return 0
	}
	return *p
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

// buildRequestContext stores the resolved identity and core service on the
// request context. When the session is an impersonation session it also tags the
// context (via core.WithImpersonation) so audit events written downstream are
// consistently marked impersonation=true with the initiating admin recorded.
func buildRequestContext(parent context.Context, userCtx *UserContext, coreService *core.KeyorixCore) context.Context {
	ctx := context.WithValue(parent, userContextKey, userCtx)
	ctx = context.WithValue(ctx, coreServiceContextKey, coreService)
	if userCtx != nil && userCtx.ImpersonatedBy != nil {
		ctx = core.WithImpersonation(ctx, *userCtx.ImpersonatedBy)
	}
	// Tag machine requests so every audit event they produce is actored as a
	// machine identity (ADR-023/030 plumbing).
	if userCtx != nil && userCtx.MachineIdentityID != nil {
		ctx = core.WithActorType(ctx, core.ActorTypeMachine)
	}
	return ctx
}

// GetUserFromContext extracts the user context from the request context
func GetUserFromContext(ctx context.Context) *UserContext {
	if userCtx, ok := ctx.Value(userContextKey).(*UserContext); ok {
		return userCtx
	}
	return nil
}

// validateToken validates a session token via the supplied validator and returns
// the resolved UserContext. Permissions are no longer precomputed here — they are
// resolved per request, scoped to the target, by core.Authorize.
func validateToken(ctx context.Context, validator sessionValidator, token string) (*UserContext, error) {
	if validator == nil {
		return nil, http.ErrNotSupported
	}
	// Machine tokens (ADR-030) authenticate AS a machine identity, not a user.
	if strings.HasPrefix(token, machineTokenPrefix) {
		m, roleNames, err := validator.ValidateMachineToken(ctx, token)
		if err != nil {
			return nil, err
		}
		mid := m.ID
		return &UserContext{
			UserID:            0,
			MachineIdentityID: &mid,
			ActorType:         core.ActorTypeMachine,
			Username:          m.Name,
			Roles:             roleNames,
			AccountState:      core.AccountActive,
		}, nil
	}

	// Route by prefix: PATs authenticate AS their owning user, resolving to the same
	// UserContext shape as a session — so authorization downstream is identical.
	var (
		user      *models.User
		roleNames []string
		err       error
	)
	if strings.HasPrefix(token, patTokenPrefix) {
		user, roleNames, err = validator.ValidatePATToken(ctx, token)
	} else {
		user, roleNames, err = validator.ValidateSessionToken(ctx, token)
	}
	if err != nil {
		return nil, err
	}
	return &UserContext{
		UserID:       user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Roles:        roleNames,
		ActorType:    core.ActorTypeUser,
		AccountState: core.NormalizeAccountState(user.AccountState),
		Restricted:   core.AccountRestricted(user.AccountState),
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

// notFoundResponse sends a 404 Not Found response.
func notFoundResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "NotFound", "message": message, "code": http.StatusNotFound,
	})
}

// badRequestResponse sends a 400 Bad Request response.
func badRequestResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "BadRequest", "message": message, "code": http.StatusBadRequest,
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
