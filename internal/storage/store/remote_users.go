// remote_users.go — User and Group operations for RemoteStorage.
//
// Covers: CreateUser, GetUser, GetUserByEmail, GetUserByUsername,
// GetUserByExternalID, UpdateUser,
//
//	DeleteUser, RestoreUser, ListUsers, GetUserGroups,
//	CreateGroup, GetGroup, UpdateGroup, DeleteGroup, RestoreGroup, ListGroups,
//	ListGroupsPage, AddUserToGroup, RemoveUserFromGroup, ListGroupMembers,
//	ListGroupMembersByGroupIDs.
//
// Group methods proxy onto NEW server-side routes under /api/v1/system/groups
// and /api/v1/system/users/{id}/groups (server/http/handlers/groups_proxy.go),
// mirroring the #452/#507 "RemoteStorage stub -> thin proxy route" pattern
// established for login-attempts and project invitations: gated on the SAME
// system.read/system.write RBAC tier every other RemoteStorage call already
// needs (no new privilege class).
//
// These deliberately do NOT reuse the existing human-facing /api/v1/groups
// routes (server/http/handlers/groups_handler.go, groups_members.go): those run
// through the CALLING server's own core.KeyorixCore (validation, audit-log
// events, and escalation-by-proxy ceilings — guardLastGlobalAdminGroupDelete,
// guardLastGlobalAdminMembership, requireGlobalAdminToReinstateAdminRoles,
// requireAuthorityForRole; internal/core/groups.go). A RemoteStorage-backed
// core.KeyorixCore already evaluates all of that itself, client-side, before
// ever calling down into this storage layer (exactly as it does against
// LocalStorage) — proxying onto the business-logic routes would run that SAME
// policy a second time on the upstream server, double-logging every mutation
// and, worse, re-evaluating the admin-ceiling checks against the UPSTREAM
// caller's own actor context (the RemoteStorage credential), not the original
// actor who is already fully vetted by the client's own core layer. The new
// routes below are raw passthroughs onto storage.Storage's own Group
// primitives instead — the same semantics local_users.go's LocalStorage
// implements — so this client's own core.KeyorixCore validation/audit/
// escalation logic remains the ONLY policy evaluation, identical to a local
// backend. For the local (GORM) equivalent see local_users.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"gorm.io/gorm"
)

// --- Wire DTOs (#496) ---
//
// models.User carries no json tags of its own (it is a GORM model, and the local
// backend never needs one) except PasswordHash's `json:"-"`. Marshaling it
// directly, as CreateUser/UpdateUser used to, produces Go field names verbatim —
// "DisplayName", "IsActive", "AccountState", "CreatedAt", ... . The real HTTP
// handlers (server/http/handlers/users_crud.go) decode into their own snake_case
// DTOs. encoding/json's decode falls back to a case-insensitive match when there is
// no exact tag match, which happens to paper over single-word fields ("Username"
// still matches a "username" tag, "Email" still matches "email") but never an
// underscore-separated one ("DisplayName" does not case-insensitively equal
// "display_name"; "IsActive" does not equal "active" at all, it is not even a
// substring match) — so those fields were silently dropped, landing at their zero
// value server-side. The wire types below name every field explicitly so nothing
// depends on that fallback (or the handler's specific field-naming choices) again.
//
// Password (#499, closing the residual gap #496 left open): models.User only
// ever carries a bcrypt PasswordHash (`json:"-"`, intentionally excluded from the
// wire — it must never be sent) by the time CreateUser is invoked;
// buildUserForCreate (internal/core/users.go) discards the plaintext once it
// computes the hash. The server's own "password is required unless
// deliver_setup_link/generate_one_time_password is set" check needs the
// PLAINTEXT (it hashes its own copy), which storage.Storage.CreateUser's new
// optional plaintextPassword variadic now carries specifically for this call —
// see the interface doc (internal/core/storage/interface.go) for why it is a
// call argument and not a models.User field. Omitted (empty string) whenever the
// caller has no real plaintext to offer (SSO/SCIM auto-provisioning), in which
// case this field is simply left out of the JSON body, exactly as before.
type userCreateWireRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	IsActive    *bool  `json:"is_active,omitempty"`
	Password    string `json:"password,omitempty"`
}

// userUpdateWireRequest mirrors UpdateUser's handler DTO exactly (all optional,
// PUT-as-PATCH semantics): only fields explicitly present are changed server-side.
type userUpdateWireRequest struct {
	Username    *string `json:"username,omitempty"`
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

func newUserCreateWireRequest(user *models.User, plaintextPassword string) userCreateWireRequest {
	active := user.IsActive
	return userCreateWireRequest{
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		IsActive:    &active,
		Password:    plaintextPassword,
	}
}

func newUserUpdateWireRequest(user *models.User) userUpdateWireRequest {
	username, email, displayName, active := user.Username, user.Email, user.DisplayName, user.IsActive
	return userUpdateWireRequest{
		Username:    &username,
		Email:       &email,
		DisplayName: &displayName,
		Active:      &active,
	}
}

// userWireResponse mirrors userToAPIResponse's snake_case wire shape
// (server/http/handlers/users_handler.go) — the actual response body every
// user-returning endpoint sends. Decoding straight into models.User (as before)
// has the identical mismatch as the request side, in reverse: "display_name",
// "active", "account_state", "created_at", "updated_at", "last_login_at" all fail
// the case-insensitive fallback against models.User's untagged field names, so
// every field but ID/Username/Email came back silently zeroed.
//
// FailedLoginAttempts/LoginLockoutCount/LastFailedLoginAt (#500) round out the
// lockout-accounting fields alongside LoginLockedUntil: LockUserForUpdate is just
// GetUser (see below) over HTTP, and checkLockAndClearLoginFailures
// (internal/core/login_lockout.go) reads all four of these off that same response
// to decide both "is this account currently locked" and its "nothing to clear"
// fast path — without them on the wire, the fast path always saw a false all-zero
// snapshot under storage.type: remote.
// ExternalID (#505) rounds out the wire response with the IdP-assigned identifier
// SCIM/SSO JIT-provisioning stamps on a user (models.User.ExternalID). Without it,
// resolveSSOUser's (internal/core/sso.go) cross-provider-takeover guard —
// ssoBoundToOtherProvider(u.ExternalID, provider), which refuses to let a SECOND
// SSO provider claim an account already linked to a different one via the
// email-fallback branch — silently never tripped under storage.type: remote: every
// decoded user's ExternalID read back as the Go zero value "", identical to a
// never-federated account, regardless of what the upstream's own row actually
// stored. This affected the already-shipped #504 email-fallback path, not just the
// new by-external-id lookup this change adds.
// MFAEnabled (#524) rounds out the wire response with the two-factor-enrolment
// flag. The server side (users_crud.go) always sent "mfa_enabled" in its
// response, but this wire type never had a field to decode it into, so every
// decoded user's MFAEnabled read back as the Go zero value (false) under
// storage.type: remote — regardless of what the upstream's own row actually
// stored. This silently broke every internal/core/mfa.go caller that branches
// on user.MFAEnabled once #524's storage-primitive proxies made the rest of
// the enrolment/management flow reachable: MFARecoveryCodesRemaining always
// reported 0/0, DisableMFA/RegenerateMFARecoveryCodes always refused with "MFA
// is not enabled", and requireReauth's TOTP-code re-auth branch (the ONLY
// re-auth path that works under storage.type: remote — its password fallback
// needs PasswordHash, which is deliberately never sent, see above) was
// unreachable dead code. A pre-existing gap in remote_users.go, not one of
// #524's eight remote_mfa.go storage methods, but load-bearing for the SAME
// described bug ("disabling [MFA], or viewing/regenerating recovery codes
// cannot work at all in this mode") and fixed in the same PR for that reason.
type userWireResponse struct {
	ID                  uint       `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	DisplayName         string     `json:"display_name"`
	Active              bool       `json:"active"`
	AccountState        string     `json:"account_state"`
	ExternalID          string     `json:"external_id"`
	MFAEnabled          bool       `json:"mfa_enabled"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	DeletedAt           *time.Time `json:"deleted_at"`
	LoginLockedUntil    *time.Time `json:"login_locked_until,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LoginLockoutCount   int        `json:"login_lockout_count"`
	LastFailedLoginAt   *time.Time `json:"last_failed_login_at"`
}

func (w userWireResponse) toModel() *models.User {
	u := &models.User{
		ID:                  w.ID,
		Username:            w.Username,
		Email:               w.Email,
		DisplayName:         w.DisplayName,
		IsActive:            w.Active,
		AccountState:        w.AccountState,
		ExternalID:          w.ExternalID,
		MFAEnabled:          w.MFAEnabled,
		CreatedAt:           w.CreatedAt,
		UpdatedAt:           w.UpdatedAt,
		LastLoginAt:         w.LastLoginAt,
		LoginLockedUntil:    w.LoginLockedUntil,
		FailedLoginAttempts: w.FailedLoginAttempts,
		LoginLockoutCount:   w.LoginLockoutCount,
		LastFailedLoginAt:   w.LastFailedLoginAt,
	}
	if w.DeletedAt != nil {
		u.DeletedAt = gorm.DeletedAt{Time: *w.DeletedAt, Valid: true}
	}
	return u
}

func decodeUserResponse(data []byte) (*models.User, error) {
	var wire userWireResponse
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// --- Users ---

// CreateUser creates a new user via remote API. plaintextPassword is optional
// (#499) — see the interface doc and userCreateWireRequest's comment above for
// why it is a call argument rather than a models.User field. At most the first
// value is used; the rest is accepted only to satisfy the variadic interface
// signature (callers pass zero or one).
func (rs *RemoteStorage) CreateUser(ctx context.Context, user *models.User, plaintextPassword ...string) (*models.User, error) {
	var password string
	if len(plaintextPassword) > 0 {
		password = plaintextPassword[0]
	}
	resp, err := rs.client.Post(ctx, apiUsersPath, newUserCreateWireRequest(user, password))
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create user failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// GetUser retrieves a user by ID via remote API.
func (rs *RemoteStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// LockUserForUpdate has no row lock to take over HTTP — each remote API call is already
// atomic server-side, and the server's own LocalStorage takes the real FOR UPDATE lock
// when it runs the lockout accounting. So this is a plain read — but, unlike GetUser, it
// deliberately does NOT go through rs.client.Get's 5-minute response cache
// (internal/storage/remote/client.go).
//
// #500: this exact call is internal/core/login_lockout.go's anti-TOCTOU recheck
// (checkLockAndClearLoginFailures) run immediately before minting a session, and
// recordFailedLogin's own read-increment-write needs the row's genuinely-current
// state, not whatever GetUser's blanket path-keyed cache last saw for up to 5
// minutes. Before this fix, LockUserForUpdate simply called GetUser and so shared
// its cache: a lock tripped by ANY caller (including this same client's own earlier
// LockUserForUpdate call for a prior failed attempt in the same burst, or an
// unrelated admin "view user" GetUser call) since the cache entry was populated
// would go completely unobserved for up to 5 minutes — silently defeating the
// recheck exactly as the finding describes, but via response-cache staleness
// rather than a missing wire field. This deliberately bypasses rs.client.Get's
// cache rather than relying on write-triggered invalidation for correctness: even
// now that UpdateLoginLockoutState (#529) genuinely proxies its write and so DOES
// invalidate the cache on success (client.go's Request), a concurrent second
// LockUserForUpdate call racing that write could still observe a cache entry
// populated between the write and its invalidation if this method went through
// the cache at all — the anti-TOCTOU recheck needs an unconditionally fresh read,
// not "usually fresh because writes happen to invalidate it".
func (rs *RemoteStorage) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%d", id)
	resp, err := rs.client.Request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// GetUserByEmail retrieves a user by email via remote API.
//
// The server registers this lookup as GET /api/v1/users/by-email with the email as
// a query parameter (mirroring GetSecretByName's #497 query-scoped convention), not
// as a path segment (#503: an earlier version of this method requested
// /api/v1/users/by-email/{email}, a route server/http/router.go never registered,
// so every call 404'd against a real server regardless of whether the user
// existed — affecting every internal/core call site that resolves a user by email
// under storage.type: remote, e.g. RBAC/SSO/SCIM lookups, not just CreateUser's
// pre-existence check).
func (rs *RemoteStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/by-email?email=%s", url.QueryEscape(email))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user by email failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// GetUserByUsername retrieves a user by username via remote API (#505).
//
// Mirrors GetUserByEmail's #503 query-parameter convention exactly: GET
// /api/v1/users/by-username?username=X, gated by the same users.read permission
// as GetUser/GetUserByEmail (server/http/router.go), with the identical generic
// NotFound response shape on a miss — a caller without users.read never reaches
// the handler at all, and one WITH users.read can already enumerate every
// username via GET /users, so this route grants no new capability at that
// permission level.
//
// Before this fix, the unconditional stub blocked far more than the SCIM/
// invitation username-derivation helpers that motivated #505's filing: Login
// (internal/core/auth.go) resolves the submitted credential's account via
// c.storage.GetUserByUsername and, unlike buildUserForCreate's deliberate
// unsupported-error tolerance, treats ANY error — including the old
// ErrUnsupportedByBackend stub — as "invalid credentials". That made every
// password login fail unconditionally under storage.type: remote, not just the
// SSO/invitation paths #505 named.
func (rs *RemoteStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/by-username?username=%s", url.QueryEscape(username))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user by username failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// GetUserByExternalID retrieves a SCIM/SSO-provisioned user by the IdP's
// externalId via remote API (#505). Same query-parameter/permission/NotFound-shape
// convention as GetUserByUsername and GetUserByEmail: GET
// /api/v1/users/by-external-id?external_id=X, gated by users.read.
//
// Before this fix, resolveSSOUser (internal/core/sso.go) and FindSCIMUser
// (internal/core/scim.go) both treat any non-not-found error from this call as a
// hard failure (storage.IsUserNotFound(err) is false for the old
// ErrUnsupportedByBackend stub), so an SSO login asserting a `sub` — or a SCIM
// PATCH/GET filtering by externalId — hard-failed unconditionally under
// storage.type: remote, never falling through to the email-based fallback either
// call site supports.
func (rs *RemoteStorage) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/by-external-id?external_id=%s", url.QueryEscape(externalID))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by external id: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user by external id failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// UpdateUser updates an existing user via remote API.
func (rs *RemoteStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	path := fmt.Sprintf("/api/v1/users/%d", user.ID)
	resp, err := rs.client.Put(ctx, path, newUserUpdateWireRequest(user))
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update user failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// userActiveTransitionWireRequest carries the full row UpdateUser already
// mutated in memory (username/email/display_name/active/updated_at) plus
// fromActive — the value UpdateUser observed via GetUser (wasActive) before
// applying any of the request's field changes — for
// UpdateUserIfActiveStateMatches's conditional write. Unlike
// userUpdateWireRequest's PATCH-style semantics, every field here is always
// meaningful: this is a full-row persist (mirroring
// TransitionMachineIdentityState's transitionMachineIdentityStateBody shape),
// not a partial update, so there is no need for optional pointers.
//
// UpdatedAt is carried explicitly (unlike userUpdateWireRequest) because this
// route is a raw storage-primitive passthrough, not the human-facing PUT
// /api/v1/users/{id} route — there is no server-side core.UpdateUser call on
// the receiving end to recompute it from the upstream's own clock, so leaving
// it off the wire would zero the column on every conditional write.
type userActiveTransitionWireRequest struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Active      bool      `json:"active"`
	UpdatedAt   time.Time `json:"updated_at"`
	FromActive  bool      `json:"from_active"`
}

// UpdateUserIfActiveStateMatches persists user's full row via a single
// conditional PUT to /api/v1/system/users/{id}/active-transition (mirroring
// TransitionMachineIdentityState's #518 `WHERE id = ? AND state = ?` pattern
// for this codebase's other TOCTOU class — see the interface doc in
// internal/core/storage/interface.go), carrying fromActive alongside so the
// upstream applies the exact SAME conditional "WHERE id = ? AND is_active = ?"
// write its own LocalStorage would. This deliberately does NOT reuse the
// human-facing PUT /api/v1/users/{id} route (UpdateUser above): that route
// re-runs the upstream's OWN core.KeyorixCore.UpdateUser end to end (including
// its own GetUser read and uniqueness checks) against the caller's request
// body — the wrong shape for a caller (this client's own core.UpdateUser) that
// has ALREADY performed all of that validation itself against proxied reads
// and only needs the FINAL persist to be atomic. Exactly the same
// raw-storage-primitive-passthrough reasoning as
// machine_identities_proxy.go's TransitionMachineIdentityStateProxy.
func (rs *RemoteStorage) UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error) {
	path := fmt.Sprintf("/api/v1/system/users/%d/active-transition", user.ID)
	body := userActiveTransitionWireRequest{
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Active:      user.IsActive,
		UpdatedAt:   user.UpdatedAt,
		FromActive:  fromActive,
	}
	return rs.putConditionalTransition(ctx, path, body, "update user active state")
}

// UpdateLastLogin is not available in remote mode — last_login_at is stamped
// server-side inside the login handler, which always runs against LocalStorage.
func (rs *RemoteStorage) UpdateLastLogin(_ context.Context, _ uint, _ time.Time) error {
	return fmt.Errorf("UpdateLastLogin not available in remote mode")
}

// SetAccountState always hard-fails: account_state has no field in the wire format
// UpdateUser sends (core.UpdateUserRequest only carries username/email/display_name/
// active — see server/http/handlers/users_crud.go and core.UpdateUser), so there is no
// way to actually persist this upstream. Returning an error here — instead of silently
// falling through to a generic write that would just no-op the field — is the whole
// point of this method (#454): setAccountState (admin suspend/reactivate) and
// UpdateSCIMUser (SCIM deprovision/reactivate) must see a hard failure, not a false
// "success" that leaves the account's login-blocking state unchanged.
func (rs *RemoteStorage) SetAccountState(_ context.Context, _ uint, _ string, _ time.Time) error {
	return fmt.Errorf("account_state cannot be persisted through remote storage: the "+
		"upstream PUT /api/v1/users/{id} endpoint does not accept this field: %w", ErrRemoteUnsupported)
}

// SetPasswordHash always hard-fails: password_hash is tagged json:"-" on models.User
// (internal/storage/models/models.go), so it never even reaches the JSON body a
// RemoteStorage UpdateUser call sends — there is no way to persist a password change
// through the remote API at all. Returning an error here — instead of falling through
// to a generic write that would just no-op the field — is the #484 analogue of
// SetAccountState above (#454): applyNewPassword (self-service ChangePassword and the
// setup-token consume flow) must see a hard failure, not a false "success" that leaves
// the stored password hash unchanged.
func (rs *RemoteStorage) SetPasswordHash(_ context.Context, _ uint, _ string, _ time.Time) error {
	return fmt.Errorf("password_hash cannot be persisted through remote storage: the "+
		"upstream PUT /api/v1/users/{id} endpoint does not accept this field: %w", ErrRemoteUnsupported)
}

// loginLockoutUpdateWireRequest mirrors server/http/handlers/login_lockout_proxy.go's
// loginLockoutUpdateProxyBody exactly — the four positional parameters
// UpdateLoginLockoutState takes, named on the wire.
type loginLockoutUpdateWireRequest struct {
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LastFailedLoginAt   *time.Time `json:"last_failed_login_at"`
	LoginLockedUntil    *time.Time `json:"login_locked_until"`
	LoginLockoutCount   int        `json:"login_lockout_count"`
}

// UpdateLoginLockoutState persists ONLY the four login-lockout accounting columns via
// a single HTTP round trip to the NEW PUT /api/v1/system/users/{id}/login-lockout
// route (server/http/handlers/login_lockout_proxy.go), closing backlog #529: this
// method used to be a hard, permanent remoteUnsupported(...) stub (#454), silently
// making per-account brute-force lockout inert for every storage.type: remote
// deployment (recordFailedLogin/checkLockAndClearLoginFailures/clearLoginFailures/
// UnlockUser in internal/core/login_lockout.go all fail OPEN — log once, continue —
// whenever this returns storage.ErrUnsupportedByBackend, exactly the "permanent
// architectural gap" treatment #452 established for the login rate limiter).
//
// This is a THIN passthrough, not a new atomic primitive: LocalStorage's own
// implementation (internal/storage/store/local_users.go) is a single unconditional
// column UPDATE with no server-side read-modify-write or compare-and-set condition —
// every caller in login_lockout.go already computes the final values itself (under
// its own LockUserForUpdate + WithTransaction + per-user loginFailureMu shard
// serialization) before calling this method, so one HTTP round trip preserves the
// LOCAL implementation's semantics exactly unchanged. Unlike
// AdvanceWebAuthnCredentialCounterProxy (a genuine compare-and-swap needing the
// entire check-then-write to run server-side in one request because
// RemoteStorage.WithTransaction is a no-op passthrough), there is no analogous race
// to reopen here.
func (rs *RemoteStorage) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error {
	path := fmt.Sprintf("/api/v1/system/users/%d/login-lockout", id)
	body := loginLockoutUpdateWireRequest{
		FailedLoginAttempts: attempts,
		LastFailedLoginAt:   lastFailedAt,
		LoginLockedUntil:    lockedUntil,
		LoginLockoutCount:   lockoutCount,
	}
	resp, err := rs.client.Put(ctx, path, body)
	if err != nil {
		return fmt.Errorf("failed to update login lockout state: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update login lockout state failed: %s", resp.Error.Error())
	}
	return nil
}

// DeleteUser deletes a user via remote API.
func (rs *RemoteStorage) DeleteUser(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/users/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete user failed: %s", resp.Error.Error())
	}
	return nil
}

// RestoreUser restores a soft-deleted user via remote API.
func (rs *RemoteStorage) RestoreUser(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/users/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore user: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore user failed: %s", resp.Error.Error())
	}
	return nil
}

// PurgeDeletedUsersBefore, PurgeDeletedProjectsBefore, PurgeDeletedEnvironmentsBefore
// (finding #520) proxy onto NEW server-side routes under
// /api/v1/system/retention (server/http/handlers/retention_proxy.go) — the SAME
// "RemoteStorage stub -> thin proxy route" pattern established for login-attempts
// (#452). See remote_secrets.go's package-level retention-proxy doc comment (next
// to PurgeDeletedSecretsBefore) for the shared atomicity/timezone analysis; each
// of these three cascades (users -> role grants/memberships/received
// shares/PATs/sessions; projects -> role grants; environments, no cascade) runs
// entirely inside the upstream server's own single storage.Storage call, so one
// HTTP round trip preserves the LOCAL implementation's own transactional
// guarantee unchanged.
func (rs *RemoteStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	return postRetentionBeforeCountResp(ctx, rs, "/api/v1/system/retention/users/purge", before, "purge deleted users")
}

func (rs *RemoteStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	return postRetentionBeforeCountResp(ctx, rs, "/api/v1/system/retention/projects/purge", before, "purge deleted projects")
}

func (rs *RemoteStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	return postRetentionBeforeCountResp(ctx, rs, "/api/v1/system/retention/environments/purge", before, "purge deleted environments")
}

// ListUsers lists users with optional filtering via remote API.
func (rs *RemoteStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	path := buildUserFilterPath(filter)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("list users failed: %s", resp.Error.Error())
	}
	var result struct {
		Users []userWireResponse `json:"users"`
		Total int64              `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	users := make([]*models.User, 0, len(result.Users))
	for _, w := range result.Users {
		users = append(users, w.toModel())
	}
	return users, result.Total, nil
}

// ListUsersInStateBefore proxies onto GET
// /api/v1/system/retention/users/stale?state=&before=<RFC3339Nano> (finding
// #520) — backing the calling server's OWN stale-account warning sweep
// (internal/core.StaleAccounts, ADR-025) against this server's real storage
// backend, the SAME "RemoteStorage stub -> thin proxy route" pattern established
// for login-attempts (#452). A READ, not a delete, so the server-side route is
// gated system.read rather than system.write (see router.go). Decodes into the
// SAME userWireResponse type ListUsers already uses, since the server's wire
// shape (userRetentionProxyWire, server/http/handlers/retention_proxy.go) is a
// deliberate field-for-field mirror.
func (rs *RemoteStorage) ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error) {
	q := url.Values{}
	q.Set("state", state)
	q.Set("before", before.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/system/retention/users/stale?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list stale users: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list stale users failed: %s", resp.Error.Error())
	}
	var result struct {
		Users []userWireResponse `json:"users"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	users := make([]*models.User, 0, len(result.Users))
	for _, w := range result.Users {
		users = append(users, w.toModel())
	}
	return users, nil
}

// roleGrantWire mirrors storage.RoleGrant's fields exactly.
type roleGrantWire struct {
	RoleID        uint `json:"role_id"`
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

func newRoleGrantWire(g storage.RoleGrant) roleGrantWire {
	return roleGrantWire{RoleID: g.RoleID, ProjectID: g.Scope.ProjectID, EnvironmentID: g.Scope.EnvironmentID}
}

// duplicateEmailProxyCode is the machine-readable error code
// CreateUserWithRoleGrantsProxy returns when the upstream's own partial
// unique-index rejection (uniq_users_email_active, #117) fires — the wire-level
// signal used below to reconstruct the same storage.ErrDuplicateEmail sentinel
// core.CreateUserWithAssignments' own errors.Is check depends on, mirroring
// legalHoldAlreadyActiveCode's identical two-package-duplicated-constant
// pattern (server/http/handlers/legal_hold_proxy.go / remote_legal_hold.go).
const duplicateEmailProxyCode = "DUPLICATE_EMAIL"

// createUserWithRoleGrantsWireRequest is the wire body for CreateUserWithRoleGrants
// (finding #531). Unlike CreateUser's userCreateWireRequest — which sends the
// PLAINTEXT password and lets the upstream handler compute its own bcrypt hash,
// because that route runs through the calling server's core.CreateUser business
// logic a second time server-side — this is a raw storage-primitive passthrough,
// exactly like AdvanceWebAuthnCredentialCounter/TransitionMachineIdentityState:
// the CALLING server's own core.CreateUserWithAssignments (internal/core/users.go)
// already ran buildUserForCreate (validation, password-policy check, bcrypt hash)
// BEFORE ever reaching storage.Storage, so PasswordHash here carries that
// already-computed hash directly — the upstream handler must persist it
// unconditionally, not re-derive it from a plaintext it was never given.
type createUserWithRoleGrantsWireRequest struct {
	Username          string          `json:"username"`
	Email             string          `json:"email"`
	DisplayName       string          `json:"display_name"`
	PasswordHash      string          `json:"password_hash"`
	IsActive          bool            `json:"is_active"`
	AccountState      string          `json:"account_state"`
	PasswordChangedAt *time.Time      `json:"password_changed_at,omitempty"`
	Grants            []roleGrantWire `json:"grants"`
}

func newCreateUserWithRoleGrantsWireRequest(user *models.User, grants []storage.RoleGrant) createUserWithRoleGrantsWireRequest {
	wireGrants := make([]roleGrantWire, 0, len(grants))
	for _, g := range grants {
		wireGrants = append(wireGrants, newRoleGrantWire(g))
	}
	return createUserWithRoleGrantsWireRequest{
		Username:          user.Username,
		Email:             user.Email,
		DisplayName:       user.DisplayName,
		PasswordHash:      user.PasswordHash,
		IsActive:          user.IsActive,
		AccountState:      user.AccountState,
		PasswordChangedAt: user.PasswordChangedAt,
		Grants:            wireGrants,
	}
}

// CreateUserWithRoleGrants creates a user and every role grant in ONE atomic
// request via POST /api/v1/system/users/with-role-grants (finding #531).
//
// Atomicity note (investigated, not assumed safe): LocalStorage.CreateUserWithRoleGrants
// wraps the user INSERT and every role-grant INSERT in a single real DB
// transaction (ADR-028) — if any grant insert fails, the user insert is rolled
// back too, so a create never leaves a half-provisioned account (a user with
// SOME but not all intended grants, or a user with grants pointing at nothing).
// RemoteStorage.WithTransaction is a no-op passthrough (remote_transaction.go —
// each remote call is independent), so naively proxying this as "POST the user,
// then POST each grant" as separate HTTP calls would silently drop that
// guarantee: a failure partway through (a bad role ID, a SoD-policy violation
// surfacing only at insert time, a network blip) would leave a user record
// committed upstream with only the grants that happened to land before the
// failure — exactly the partial-provisioning bug ADR-028's transaction exists to
// prevent, reopened by composing two independent round trips. Instead, this is
// ONE PATCH-equivalent POST whose server-side handler
// (CreateUserWithRoleGrantsProxy, server/http/handlers/misc_remote_proxy.go)
// calls storage.Storage.CreateUserWithRoleGrants DIRECTLY against THIS server's
// own storage inside that single request — the real atomicity is achieved
// server-side in one round trip, not orchestrated client-side across several,
// mirroring AdvanceWebAuthnCredentialCounter's (#517) and
// TransitionMachineIdentityState's (#518) identical "new atomic primitive,
// not a naive multi-call proxy" precedent.
//
// A duplicate-email race (uniq_users_email_active, #117) is translated back
// into storage.ErrDuplicateEmail from the wire-level duplicateEmailProxyCode
// (see #501's note on makeRequest collapsing every 4xx/5xx into a non-nil
// error before resp is ever populated — the same recovery-from-*remote.HTTPError
// pattern remote_legal_hold.go's CreateLegalHold already uses), so
// core.CreateUserWithAssignments' own errors.Is(err, storage.ErrDuplicateEmail)
// check is preserved across this HTTP hop exactly as it is for a local backend.
func (rs *RemoteStorage) CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []storage.RoleGrant) (*models.User, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/users/with-role-grants", newCreateUserWithRoleGrantsWireRequest(user, grants))
	if err != nil {
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) && httpErr.ErrorType == duplicateEmailProxyCode {
			return nil, fmt.Errorf("%w: %s", storage.ErrDuplicateEmail, httpErr.Message)
		}
		return nil, fmt.Errorf("failed to create user with role grants: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create user with role grants failed: %s", resp.Error.Error())
	}
	return decodeUserResponse(resp.Data)
}

// buildUserFilterPath constructs the /api/v1/users query string.
func buildUserFilterPath(filter *storage.UserFilter) string {
	if filter == nil {
		return apiUsersPath
	}
	params := newQueryBuilder()
	params.addString("search", filter.Search)
	params.addString("username", filter.Username)
	params.addString("email", filter.Email)
	params.addBool("is_active", filter.IsActive)
	params.addTime("created_after", filter.CreatedAfter)
	params.addPage(filter.Page, filter.PageSize)
	return apiUsersPath + params.String()
}

// --- Group wire DTOs ---
//
// models.Group carries no json tags of its own (the same #496 class of gap as
// models.User/models.ProjectInvitation), so a direct marshal would send Go
// field names verbatim ("Name" and "Description" happen to survive the
// case-insensitive decode fallback since they are single words, but
// CreatedAt/UpdatedAt/DeletedAt would collide with server/http/handlers'
// snake_case wire shape). Named explicitly instead, matching every other
// RemoteStorage wire DTO in this codebase.
type groupWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newGroupWire(g *models.Group) groupWire {
	w := groupWire{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
	if g.DeletedAt.Valid {
		t := g.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

func (w groupWire) toModel() *models.Group {
	g := &models.Group{
		ID:          w.ID,
		Name:        w.Name,
		Description: w.Description,
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
	if w.DeletedAt != nil {
		g.DeletedAt = gorm.DeletedAt{Time: *w.DeletedAt, Valid: true}
	}
	return g
}

func decodeGroupResponse(data []byte) (*models.Group, error) {
	var wire groupWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// GetUserGroups returns all groups a user belongs to via GET
// /api/v1/system/users/{id}/groups.
//
// Before this fix this unconditionally returned an empty slice instead of an
// error — a "silent data loss" shape of bug, not a loud failure: every caller
// (internal/core/permissions.go's effective-permission resolution,
// internal/core/sso.go's group-membership sync, internal/core/
// access_review_campaign.go) silently saw "this user belongs to zero groups"
// under storage.type: remote, regardless of the upstream's real membership
// data — under-granting every group-inherited role/permission with no error
// surfaced anywhere, rather than the server genuinely having no groups
// subsystem at all.
func (rs *RemoteStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	path := fmt.Sprintf("/api/v1/system/users/%d/groups", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user groups failed: %s", resp.Error.Error())
	}
	var result struct {
		Groups []groupWire `json:"groups"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	groups := make([]*models.Group, 0, len(result.Groups))
	for _, w := range result.Groups {
		groups = append(groups, w.toModel())
	}
	return groups, nil
}

// --- Groups ---

// CreateGroup creates a new group via POST /api/v1/system/groups — a raw
// persist onto storage.Storage.CreateGroup, not the human-facing POST
// /api/v1/groups (see the package doc for why).
func (rs *RemoteStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/groups", newGroupWire(group))
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create group failed: %s", resp.Error.Error())
	}
	return decodeGroupResponse(resp.Data)
}

// GetGroup retrieves a group by ID via GET /api/v1/system/groups/{id}.
func (rs *RemoteStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	path := fmt.Sprintf("/api/v1/system/groups/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get group failed: %s", resp.Error.Error())
	}
	return decodeGroupResponse(resp.Data)
}

// UpdateGroup updates an existing group via PUT /api/v1/system/groups/{id}.
func (rs *RemoteStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	path := fmt.Sprintf("/api/v1/system/groups/%d", group.ID)
	resp, err := rs.client.Put(ctx, path, newGroupWire(group))
	if err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update group failed: %s", resp.Error.Error())
	}
	return decodeGroupResponse(resp.Data)
}

// DeleteGroup soft-deletes a group via DELETE /api/v1/system/groups/{id}.
func (rs *RemoteStorage) DeleteGroup(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/groups/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete group failed: %s", resp.Error.Error())
	}
	return nil
}

// RestoreGroup reverses a soft-delete via POST /api/v1/system/groups/{id}/restore.
func (rs *RemoteStorage) RestoreGroup(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/groups/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore group failed: %s", resp.Error.Error())
	}
	return nil
}

// ListGroups lists every group via GET /api/v1/system/groups.
func (rs *RemoteStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/groups")
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list groups failed: %s", resp.Error.Error())
	}
	var result struct {
		Groups []groupWire `json:"groups"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	groups := make([]*models.Group, 0, len(result.Groups))
	for _, w := range result.Groups {
		groups = append(groups, w.toModel())
	}
	return groups, nil
}

// ListGroupsPage returns one name-ordered page of groups and the total count
// via GET /api/v1/system/groups/page?offset=&limit=.
func (rs *RemoteStorage) ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error) {
	path := fmt.Sprintf("/api/v1/system/groups/page?offset=%d&limit=%d", offset, pageSize)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups page: %w", err)
	}
	if !resp.Success {
		return nil, 0, fmt.Errorf("list groups page failed: %s", resp.Error.Error())
	}
	var result struct {
		Groups []groupWire `json:"groups"`
		Total  int64       `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	groups := make([]*models.Group, 0, len(result.Groups))
	for _, w := range result.Groups {
		groups = append(groups, w.toModel())
	}
	return groups, result.Total, nil
}

// AddUserToGroup adds userID to groupID scoped to projectID via POST
// /api/v1/system/groups/{id}/members. projectID=0 creates a global membership.
func (rs *RemoteStorage) AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error {
	path := fmt.Sprintf("/api/v1/system/groups/%d/members", groupID)
	body := struct {
		UserID    uint `json:"user_id"`
		ProjectID uint `json:"project_id"`
	}{UserID: userID, ProjectID: projectID}
	resp, err := rs.client.Post(ctx, path, body)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("add user to group failed: %s", resp.Error.Error())
	}
	return nil
}

// RemoveUserFromGroup removes the (userID, groupID, projectID) membership via
// DELETE /api/v1/system/groups/{id}/members/{userId}?project_id={projectID}.
func (rs *RemoteStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error {
	path := fmt.Sprintf("/api/v1/system/groups/%d/members/%d?project_id=%d", groupID, userID, projectID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove user from group failed: %s", resp.Error.Error())
	}
	return nil
}

// ListGroupMembers lists a group's members via GET
// /api/v1/system/groups/{id}/members.
func (rs *RemoteStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	path := fmt.Sprintf("/api/v1/system/groups/%d/members", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list group members failed: %s", resp.Error.Error())
	}
	var result struct {
		Members []userWireResponse `json:"members"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	users := make([]*models.User, 0, len(result.Members))
	for _, w := range result.Members {
		users = append(users, w.toModel())
	}
	return users, nil
}

// ListGroupMembersByGroupIDs is the batch form of ListGroupMembers via GET
// /api/v1/system/groups/members-by-ids?ids=1,2,3 — one HTTP round trip for
// every group ID, matching LocalStorage's single-query batch behavior (used by
// the rotation planner's risk-scoring batch, #409).
func (rs *RemoteStorage) ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error) {
	out := make(map[uint][]*models.User, len(groupIDs))
	if len(groupIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		ids = append(ids, strconv.FormatUint(uint64(id), 10))
	}
	path := "/api/v1/system/groups/members-by-ids?ids=" + url.QueryEscape(strings.Join(ids, ","))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members by IDs: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list group members by IDs failed: %s", resp.Error.Error())
	}
	var result map[string][]userWireResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	for key, members := range result {
		groupID, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			continue
		}
		users := make([]*models.User, 0, len(members))
		for _, w := range members {
			users = append(users, w.toModel())
		}
		out[uint(groupID)] = users
	}
	return out, nil
}

// --- Password history (ADR-025) ---
// Password changes are processed server-side in remote mode, so history is
// recorded and checked there; these are stubs.

func (rs *RemoteStorage) AddPasswordHistory(_ context.Context, _ uint, _ string, _ time.Time) error {
	return nil
}

func (rs *RemoteStorage) RecentPasswordHashes(_ context.Context, _ uint, _ int) ([]string, error) {
	return nil, nil
}

func (rs *RemoteStorage) PrunePasswordHistory(_ context.Context, _ uint, _ int) error {
	return nil
}
