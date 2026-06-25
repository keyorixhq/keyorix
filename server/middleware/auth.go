package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	ValidatePATToken(ctx context.Context, token string) (*models.User, []string, *core.PATRestriction, error)
	ValidateMachineToken(ctx context.Context, token string) (*models.MachineIdentity, []string, error)
	ValidateOIDCToken(ctx context.Context, token string) (*models.MachineIdentity, []string, error)
	OIDCEnabled() bool
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
	// MFAEnabled is true when the user has any second factor enabled (TOTP or a
	// passkey); SessionAuth is true only for an interactive session token (false for
	// PAT / machine / OIDC). Together they drive EnforceMFAEnrollment, which must not
	// confine non-interactive automation.
	MFAEnabled  bool `json:"-"`
	SessionAuth bool `json:"-"`
	// PATRestriction is the least-privilege filter a personal access token imposes
	// (ADR-042), or nil for sessions / unrestricted PATs. Cached with the rest of
	// the identity and tagged onto the request context by buildRequestContext so
	// core.Authorize enforces it at the single authorization chokepoint.
	PATRestriction *core.PATRestriction `json:"-"`
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
				// The network allowlist is per-request (the same token may arrive from a
				// different IP), so enforce it even on a cache hit.
				if !tokenNetworkAllowed(r, entry.userCtx) {
					forbiddenResponse(w, "token not permitted from this network")
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
			if coreService != nil && !strings.HasPrefix(token, patTokenPrefix) && !strings.HasPrefix(token, machineTokenPrefix) && !looksLikeJWT(token) {
				userCtx.ImpersonatedBy = coreService.SessionImpersonator(r.Context(), token)
			}

			// Cache the positive result.
			cacheSet(key, tokenCacheEntry{userCtx: userCtx, expiresAt: time.Now().Add(validTokenTTL)})

			if !tokenNetworkAllowed(r, userCtx) {
				forbiddenResponse(w, "token not permitted from this network")
				return
			}
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
			// Per-project MFA policy (ADR-037): deny an interactive session without a
			// second factor access to a project that requires MFA.
			if ProjectMFABlocked(r, cs, scope.ProjectID) {
				projectMFARequiredResponse(w)
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

// mfaEnrollAllowedSuffixes are the only endpoints an interactive user who must
// still enrol MFA (the security.require_mfa policy is on) may reach, beyond logout.
var mfaEnrollAllowedSuffixes = []string{
	"/auth/mfa/enroll",
	"/auth/mfa/activate",
	"/auth/webauthn/register/begin",
	"/auth/webauthn/register/finish",
	"/auth/webauthn/credentials",
	"/auth/profile",
}

// EnforceMFAEnrollment confines an interactive (session-authenticated) human user
// who has not enabled MFA to the MFA-enrolment endpoints when the deployment
// requires MFA (security.require_mfa). Non-interactive credentials — personal
// access tokens, machine tokens, OIDC — are deliberately exempt so automation is
// not broken; password-restricted sessions are handled first by
// EnforceAccountRestriction. Applied after Authentication in the authed group.
func EnforceMFAEnrollment(requireMFA bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if !requireMFA || userCtx == nil || !userCtx.SessionAuth || userCtx.MFAEnabled {
				next.ServeHTTP(w, r)
				return
			}
			for _, suffix := range mfaEnrollAllowedSuffixes {
				if strings.HasSuffix(r.URL.Path, suffix) {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "MFAEnrollmentRequired",
				"message": "This deployment requires multi-factor authentication. Enrol MFA to continue.",
				"code":    http.StatusForbidden,
			})
		})
	}
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

// ScopeFromRefQuery resolves scope from a "?ref=project/environment/name" query param,
// for the by-reference value read. It locates the referenced secret (no value read, no
// read-count side effect) and returns its project/environment scope, so the standard
// scoped-permission gate authorizes the caller against the secret's real scope — a
// caller scoped to another project is denied exactly as for the by-id route.
func ScopeFromRefQuery(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
	secret, err := cs.ResolveSecretRef(r.Context(), r.URL.Query().Get("ref"))
	if err != nil {
		if errors.Is(err, core.ErrSecretRefInvalid) {
			return core.Scope{}, errInvalidTarget
		}
		return core.Scope{}, errTargetNotFound
	}
	return core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}, nil
}

// ScopeFromDeletedSecretParam resolves the scope of a secret that may be
// soft-deleted (loads it Unscoped). Used by the restore route, where the target
// secret is by definition soft-deleted and unloadable via the normal path.
func ScopeFromDeletedSecretParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		secret, err := cs.Storage().GetSecretIncludingDeleted(r.Context(), id)
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

// RequireRole returns a middleware that checks if the user has a specific role.
//
// A request authenticated by a PAT carrying a least-privilege restriction
// (ADR-042) is denied outright: a role gate confers the role's full breadth,
// which a deliberately-scoped token must not satisfy. This keeps PAT scoping
// honoured on this role-based gate, which does not funnel through core.Authorize
// (where the restriction is otherwise enforced). Fail-closed.
func RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}
			if userCtx.PATRestriction != nil {
				forbiddenResponse(w, "A scoped personal access token cannot satisfy a role requirement")
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
	// Carry a PAT's least-privilege restriction (ADR-042) so core.Authorize
	// enforces it on every authorization check this request makes.
	if userCtx != nil && userCtx.PATRestriction != nil {
		ctx = core.WithPATRestriction(ctx, userCtx.PATRestriction)
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

// machineUserContext builds the request principal for a machine identity (used
// by both opaque machine tokens and federated OIDC tokens) — UserID 0, the
// machine id, and ActorType machine_identity so RBAC and audit are identical.
func machineUserContext(m *models.MachineIdentity, roleNames []string) *UserContext {
	mid := m.ID
	return &UserContext{
		UserID:            0,
		MachineIdentityID: &mid,
		ActorType:         core.ActorTypeMachine,
		Username:          m.Name,
		Roles:             roleNames,
		AccountState:      core.AccountActive,
	}
}

// looksLikeJWT reports whether a bearer is a three-segment dotted JWT and not a
// kx_-prefixed Keyorix credential.
func looksLikeJWT(token string) bool {
	if strings.HasPrefix(token, machineTokenPrefix) || strings.HasPrefix(token, patTokenPrefix) {
		return false
	}
	return strings.Count(token, ".") == 2
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
		return machineUserContext(m, roleNames), nil
	}

	// Federated OIDC / Kubernetes-JWT tokens (ADR-031) also authenticate AS a
	// machine identity. A JWT is a three-segment dotted token and is not one of
	// the kx_ prefixes; only attempt it when OIDC is configured.
	if validator.OIDCEnabled() && looksLikeJWT(token) {
		m, roleNames, err := validator.ValidateOIDCToken(ctx, token)
		if err != nil {
			return nil, err
		}
		return machineUserContext(m, roleNames), nil
	}

	// Route by prefix: PATs authenticate AS their owning user, resolving to the same
	// UserContext shape as a session — so authorization downstream is identical.
	var (
		user        *models.User
		roleNames   []string
		restriction *core.PATRestriction
		err         error
		viaSession  bool
	)
	if strings.HasPrefix(token, patTokenPrefix) {
		user, roleNames, restriction, err = validator.ValidatePATToken(ctx, token)
	} else {
		user, roleNames, err = validator.ValidateSessionToken(ctx, token)
		viaSession = true
	}
	if err != nil {
		return nil, err
	}
	return &UserContext{
		UserID:         user.ID,
		Username:       user.Username,
		Email:          user.Email,
		Roles:          roleNames,
		ActorType:      core.ActorTypeUser,
		AccountState:   core.NormalizeAccountState(user.AccountState),
		Restricted:     core.AccountRestricted(user.AccountState),
		MFAEnabled:     user.MFAEnabled || user.WebAuthnEnabled,
		SessionAuth:    viaSession,
		PATRestriction: restriction,
	}, nil
}

// tokenNetworkAllowed enforces a token's IP allowlist (ADR: PAT network restriction). It
// returns true when the token has no allowlist; otherwise the request's source IP must fall
// within one of the allowed CIDRs. It fails CLOSED — an undeterminable/unparseable source
// IP is denied. The source IP is the TCP peer (r.RemoteAddr), never a client-supplied
// header, so the control cannot be spoofed; a deployment behind a proxy must terminate so
// RemoteAddr is the real client (e.g. PROXY protocol) for per-client allowlists to apply.
func tokenNetworkAllowed(r *http.Request, userCtx *UserContext) bool {
	if userCtx == nil || userCtx.PATRestriction == nil || len(userCtx.PATRestriction.AllowedCIDRs) == 0 {
		return true
	}
	return core.IPInCIDRs(clientIP(r), userCtx.PATRestriction.AllowedCIDRs)
}

// clientIP returns the source IP of the request from its TCP peer address.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr // already a bare IP (or empty)
}

// unauthorizedResponse sends a 401 Unauthorized response
func unauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Unauthorized", "message": message, "code": http.StatusUnauthorized,
	})
}

// BlockWhenImpersonating refuses a request made under an impersonation session. It
// guards the target's credential-issuing / authenticator-lifecycle self-service routes
// (mint a PAT, enroll/disable MFA, register a passkey) so an admin impersonating a user
// cannot plant a durable credential that outlives the bounded, audited impersonation
// session. Impersonation is for acting AS the user for support, not administering their
// long-lived credentials.
func BlockWhenImpersonating(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := GetUserFromContext(r.Context()); u != nil && u.ImpersonatedBy != nil {
			forbiddenResponse(w, "this action is not permitted while impersonating")
			return
		}
		next.ServeHTTP(w, r)
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

// ProjectMFABlocked reports whether the request must be denied by a project's
// per-project MFA policy (ADR-037): true only when the caller is an interactive
// session WITHOUT a second factor and the scoped project requires MFA. The
// project lookup is skipped unless the caller could actually be subject to the
// policy, so MFA-backed and non-interactive (PAT / machine / OIDC) callers pay no
// cost and stay exempt — consistent with EnforceMFAEnrollment. Handlers that
// authorize in-handler (not via RequireScopedPermission) call this too, so the
// policy is enforced uniformly across every project-scoped path.
func ProjectMFABlocked(r *http.Request, cs *core.KeyorixCore, projectID uint) bool {
	if projectID == 0 || cs == nil {
		return false
	}
	userCtx := GetUserFromContext(r.Context())
	if userCtx == nil || !userCtx.SessionAuth || userCtx.MFAEnabled {
		return false
	}
	req, err := cs.ProjectRequiresMFA(r.Context(), projectID)
	return err == nil && req
}

// WriteProjectMFARequired writes the 403 ProjectMFARequired response (exported so
// in-handler authorizers can emit the same body as the scoped-permission path).
func WriteProjectMFARequired(w http.ResponseWriter) { projectMFARequiredResponse(w) }

// projectMFARequiredResponse sends a 403 with a distinct code so the client can
// prompt the user to enrol a second factor (ADR-037 per-project MFA policy).
func projectMFARequiredResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "ProjectMFARequired",
		"message": "This project requires multi-factor authentication. Enrol a second factor to access it.",
		"code":    http.StatusForbidden,
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
	InvalidateTokenCacheByHash(tokenKey(token))
}

// InvalidateTokenCacheByHash evicts the entry keyed by the token's SHA-256 hash (hex).
// PAT revocation works by token ID and never sees the raw token, but a PAT's stored
// TokenHash equals this cache key, so revoke-by-id can purge the entry immediately
// rather than waiting out the positive-cache TTL.
func InvalidateTokenCacheByHash(hash string) {
	tokenCacheMu.Lock()
	delete(tokenCache, hash)
	tokenCacheMu.Unlock()
}
