// remote_users.go — User and Group operations for RemoteStorage.
//
// Covers: CreateUser, GetUser, GetUserByEmail, GetUserByUsername,
// GetUserByExternalID, UpdateUser,
//
//	DeleteUser, RestoreUser, ListUsers, GetUserGroups,
//	CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
//	AddUserToGroup, RemoveUserFromGroup, ListGroupMembers.
//
// Group methods (CreateGroup … ListGroupMembers) are stubs — not yet implemented
// on the remote API. For the local (GORM) equivalent see local_users.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
type userWireResponse struct {
	ID                  uint       `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	DisplayName         string     `json:"display_name"`
	Active              bool       `json:"active"`
	AccountState        string     `json:"account_state"`
	ExternalID          string     `json:"external_id"`
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
	resp, err := rs.client.Post(ctx, "/api/v1/users", newUserCreateWireRequest(user, password))
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
// rather than a missing wire field. Cache invalidation on write (client.go's
// Request) does not help here either: RemoteStorage's own write path for these
// columns (UpdateLoginLockoutState) is a hard, permanent stub (#454) that never
// makes an HTTP call at all, so it can never trigger that invalidation.
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

// UpdateLoginLockoutState always returns ErrRemoteUnsupported: none of the four
// login-lockout columns are expressible in the wire format either (#454), so, unlike
// SetAccountState above, the caller (login_lockout.go) treats this as the same
// "permanent architectural gap" #452 already established for the login rate limiter —
// log a loud one-time operator warning and fail OPEN, rather than blocking every login
// under storage.type: remote.
func (rs *RemoteStorage) UpdateLoginLockoutState(_ context.Context, _ uint, _ int, _, _ *time.Time, _ int) error {
	return remoteUnsupported("UpdateLoginLockoutState")
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

// Retention purge runs server-side (ADR-032); not available in remote mode.
func (rs *RemoteStorage) PurgeDeletedUsersBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedUsersBefore")
}

func (rs *RemoteStorage) PurgeDeletedProjectsBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedProjectsBefore")
}

func (rs *RemoteStorage) PurgeDeletedEnvironmentsBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PurgeDeletedEnvironmentsBefore")
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

func (rs *RemoteStorage) ListUsersInStateBefore(_ context.Context, _ string, _ time.Time) ([]*models.User, error) {
	return nil, remoteUnsupported("ListUsersInStateBefore")
}

func (rs *RemoteStorage) CreateUserWithRoleGrants(_ context.Context, _ *models.User, _ []storage.RoleGrant) (*models.User, error) {
	return nil, remoteUnsupported("CreateUserWithRoleGrants")
}

// buildUserFilterPath constructs the /api/v1/users query string.
func buildUserFilterPath(filter *storage.UserFilter) string {
	if filter == nil {
		return "/api/v1/users"
	}
	params := newQueryBuilder()
	params.addString("search", filter.Search)
	params.addString("username", filter.Username)
	params.addString("email", filter.Email)
	params.addBool("is_active", filter.IsActive)
	params.addTime("created_after", filter.CreatedAfter)
	params.addPage(filter.Page, filter.PageSize)
	return "/api/v1/users" + params.String()
}

// GetUserGroups returns all groups a user belongs to.
// Returns an empty slice — group membership resolution is not yet implemented remotely.
func (rs *RemoteStorage) GetUserGroups(_ context.Context, _ uint) ([]*models.Group, error) {
	return []*models.Group{}, nil
}

// --- Groups (stubs — not yet implemented on remote API) ---

func (rs *RemoteStorage) CreateGroup(_ context.Context, _ *models.Group) (*models.Group, error) {
	return nil, remoteUnsupported("CreateGroup")
}

func (rs *RemoteStorage) GetGroup(_ context.Context, _ uint) (*models.Group, error) {
	return nil, remoteUnsupported("GetGroup")
}

func (rs *RemoteStorage) UpdateGroup(_ context.Context, _ *models.Group) (*models.Group, error) {
	return nil, remoteUnsupported("UpdateGroup")
}

func (rs *RemoteStorage) DeleteGroup(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteGroup")
}

func (rs *RemoteStorage) RestoreGroup(_ context.Context, _ uint) error {
	return remoteUnsupported("RestoreGroup")
}

func (rs *RemoteStorage) ListGroups(_ context.Context) ([]*models.Group, error) {
	return nil, remoteUnsupported("ListGroups")
}

func (rs *RemoteStorage) ListGroupsPage(_ context.Context, _, _ int) ([]*models.Group, int64, error) {
	return nil, 0, remoteUnsupported("ListGroupsPage")
}

func (rs *RemoteStorage) AddUserToGroup(_ context.Context, _, _ uint) error {
	return remoteUnsupported("AddUserToGroup")
}

func (rs *RemoteStorage) RemoveUserFromGroup(_ context.Context, _, _ uint) error {
	return remoteUnsupported("RemoveUserFromGroup")
}

func (rs *RemoteStorage) ListGroupMembers(_ context.Context, _ uint) ([]*models.User, error) {
	return nil, remoteUnsupported("ListGroupMembers")
}

// ListGroupMembersByGroupIDs is the batch form of ListGroupMembers, which is itself
// unsupported in remote mode — so is this, for the same reason (group membership is
// server-side only). Matches ListGroupMembers' existing per-group unsupported error:
// a caller (the rotation planner's risk-scoring batch, #409) already degrades a
// secret's exposure factor to the worst case on this error, exactly as it already
// does today when a group share's ListGroupMembers call fails in remote mode.
func (rs *RemoteStorage) ListGroupMembersByGroupIDs(_ context.Context, _ []uint) (map[uint][]*models.User, error) {
	return nil, remoteUnsupported("ListGroupMembersByGroupIDs")
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
