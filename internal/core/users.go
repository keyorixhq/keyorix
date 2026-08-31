// users.go — User CRUD, list, and validation.
//
// CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser, ListUsers, GetUserByEmail.
// For group operations see groups.go. Types are in users_types.go.
package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// emailRegex/usernameMinLen/usernameMaxLen/displayNameMinLen/displayNameMaxLen
// mirror the exact format rules server/http/handlers' request-body `validate`
// struct tags enforce for username/email/display_name (users_handler.go,
// users_crud.go) — NOT internal/core/users_types.go's CreateUserRequest.validate
// tags, which are unread dead documentation (no validator library in this
// codebase resolves them) and, for Username, actually claim a stricter
// `alphanum` rule the live HTTP path never enforces. Duplicated here rather
// than imported from server/validation (which internal/core does not, and per
// this repo's layering should not, depend on) so gRPC and CLI embedded-mode —
// which construct a CreateUserRequest/UpdateUserRequest directly and never
// route through the HTTP JSON decoder's validator — get the identical format
// guarantee the HTTP path already has (G38).
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

const (
	usernameMinLen    = 3
	usernameMaxLen    = 50
	displayNameMinLen = 1
	displayNameMaxLen = 100
)

func validateUsernameFormat(username string) error {
	if len(username) < usernameMinLen || len(username) > usernameMaxLen {
		return fmt.Errorf("%s: username must be between %d and %d characters", i18n.T("ErrorValidation", nil), usernameMinLen, usernameMaxLen)
	}
	return nil
}

func validateEmailFormat(email string) error {
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), i18n.T("LabelEmail", nil))
	}
	return nil
}

func validateDisplayNameFormat(displayName string) error {
	if len(displayName) < displayNameMinLen || len(displayName) > displayNameMaxLen {
		return fmt.Errorf("%s: display name must be between %d and %d characters", i18n.T("ErrorValidation", nil), displayNameMinLen, displayNameMaxLen)
	}
	return nil
}

// ProjectAssignment grants Role to the new user at a project's scope, applied
// atomically with the user create (ADR-028).
type ProjectAssignment struct {
	ProjectID uint
	Role      string
}

// buildUserForCreate validates the request and constructs the (unsaved) user
// record plus its bcrypt hash. Shared by CreateUser and CreateUserWithAssignments.
func (c *KeyorixCore) buildUserForCreate(ctx context.Context, req *CreateUserRequest) (*models.User, string, error) {
	if err := c.validateCreateUserRequest(req); err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	// Enforce the configured password policy on the admin-supplied password — the same
	// policy BootstrapSystem and ChangePassword apply. Without this, the admin "classic"
	// create path (the one path where a human picks the credential) silently accepted a
	// weak password, which is then exposed to online guessing. The policy's user context
	// also catches username/email-in-password. ADR-025.
	policyUser := &models.User{Username: req.Username, Email: req.Email, DisplayName: displayName}
	if err := c.passwordPolicy.Validate(req.Password, policyUser); err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), int(bcryptCost.Load()))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, "", fmt.Errorf("%w: username already exists", ErrUserAlreadyExists)
	} else if !errors.Is(err, storage.ErrUnsupportedByBackend) && !storage.IsUserNotFound(err) {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// RemoteStorage.GetUserByUsername is unimplemented (ErrUnsupportedByBackend, #499):
	// it has no by-username lookup route to call. Rather than hard-failing every
	// remote CreateUser on a pre-check the backend can't perform, skip it here — the
	// upstream server's own CreateUser handler runs this exact same buildUserForCreate
	// check against its own LocalStorage when it receives the forwarded request, so the
	// duplicate-username invariant is still enforced authoritatively, just on the other
	// side of the wire instead of redundantly on both.

	existing, err := c.storage.GetUserByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, "", fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
	}
	if err != nil && !storage.IsUserNotFound(err) {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	now := c.now()
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	user := &models.User{
		Username:          req.Username,
		Email:             req.Email,
		DisplayName:       displayName,
		PasswordHash:      string(hash),
		IsActive:          active,
		AccountState:      NormalizeAccountState(req.AccountState), // empty → active (ADR-025)
		PasswordChangedAt: &now,                                    // baseline for max-age expiry (ADR-025)
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	return user, string(hash), nil
}

// CreateUser creates a new user with business logic validation. It auto-assigns
// the system_viewer baseline role (best-effort). For atomic create-with-role and
// project assignments see CreateUserWithAssignments.
func (c *KeyorixCore) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	user, hash, err := c.buildUserForCreate(ctx, req)
	if err != nil {
		return nil, err
	}

	// req.Password is forwarded as the optional plaintext argument (#499): LocalStorage
	// ignores it (a no-op — it already has the hash above), while RemoteStorage forwards
	// it over the wire so the real upstream handler can hash its own copy. This covers
	// every core.CreateUser caller uniformly (the admin classic path, CreateUserWithSetupLink,
	// and CreateUserWithOneTimePassword all populate req.Password with a real, hashable
	// string before reaching here — see buildUserForCreate above and setup_delivery.go),
	// and it is never logged.
	createdUser, err := c.storage.CreateUser(ctx, user, req.Password)
	if err != nil {
		// #117: the pre-check above (GetUserByEmail) is a check-then-act read that races
		// with a concurrent create for the identical email — both can pass it before
		// either commits. The DB-level partial unique index (uniq_users_email_active)
		// catches the loser here and CreateUser wraps it in ErrDuplicateEmail; surface the
		// same clean "email already in use" error the winner's sequential check would have
		// produced, instead of a raw constraint-violation message or an ambiguous
		// duplicate-email row.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Seed password history with the initial password so the no-reuse rule
	// (ADR-025) counts it. Best-effort — user creation has already succeeded.
	if c.passwordPolicy.HistoryCount > 0 {
		_ = c.storage.AddPasswordHistory(ctx, createdUser.ID, hash, c.now())
	}

	// Auto-assign the system_viewer role (ADR-021): a minimal install-wide
	// baseline. Failure is non-fatal — the user is created regardless.
	if role, err := c.storage.GetRoleByName(ctx, "system_viewer"); err == nil {
		_ = c.storage.AssignRole(ctx, createdUser.ID, role.ID, Scope{})
	}

	return createdUser, nil
}

// maxUserCreateAssignments bounds how many project-scoped role assignments a
// single CreateUserWithAssignments call may carry. Each entry costs at least
// one GetRole/rolePermissionNameSet round trip via
// requireGrantSetNoSoDViolation's SoD evaluation below; an unbounded
// assignments list submitted in one request is a per-request
// resource-exhaustion vector, the same class of bug as
// maxBulkAccessRequestBatchSize (internal/core/bulk_access_requests.go).
const maxUserCreateAssignments = 500

// CreateUserWithAssignments creates a user and grants a system role plus a set of
// project-scoped roles in one transaction (ADR-028 atomic provisioning). All role
// names and project IDs are resolved and validated up front, so an invalid input
// fails before anything is written; a storage failure mid-way rolls everything
// back. systemRole defaults to system_viewer when empty.
//
// #480: this is InviteGlobal's sibling — both mint a system role plus a set of
// project assignments in one call, and both need the identical escalation-by-proxy
// ceiling (requireAuthorityForRole): the generic roles.assign permission that gates
// the HTTP/gRPC entry points is a plain, non-admin-gated permission grantable to
// any custom role, so without this check a non-admin roles.assign holder could
// mint a brand-new super_admin account directly — no invite/accept step an admin
// could notice or revoke in between, unlike InviteGlobal.
func (c *KeyorixCore) CreateUserWithAssignments(ctx context.Context, req *CreateUserRequest, systemRole string, assignments []ProjectAssignment, actorID uint) (*models.User, error) {
	if len(assignments) > maxUserCreateAssignments {
		return nil, fmt.Errorf("assignments exceeds the maximum batch size of %d", maxUserCreateAssignments)
	}
	user, hash, err := c.buildUserForCreate(ctx, req)
	if err != nil {
		return nil, err
	}

	// Resolve every grant before touching the database. Dedup by role+project so a
	// repeated assignment can't trip the unique constraint inside the transaction.
	grants := make([]storage.RoleGrant, 0, len(assignments)+1)
	seen := map[[2]uint]bool{}

	sysRole := systemRole
	if sysRole == "" {
		sysRole = "system_viewer"
	}
	sr, err := c.storage.GetRoleByName(ctx, sysRole)
	if err != nil {
		return nil, fmt.Errorf("%s: unknown role %q (system)", i18n.T("ErrorValidation", nil), sysRole)
	}
	// Escalation-by-proxy guard (#480), mirroring InviteGlobal (#231): a global
	// system role is the most powerful grant this flow can mint, so it needs the
	// same admin-authority ceiling check, at global scope (projectID 0).
	if err := c.requireAuthorityForRole(ctx, actorID, 0, sysRole); err != nil {
		return nil, err
	}
	addRoleGrant(&grants, seen, sr.ID, 0)

	for _, a := range assignments {
		g, err := c.resolveProjectRoleGrant(ctx, actorID, a)
		if err != nil {
			return nil, err
		}
		addRoleGrant(&grants, seen, g.RoleID, g.Scope.ProjectID)
	}

	// #419: the separation-of-duties preventive gate. A brand-new user has no
	// prior grants to check against (requireNoSoDViolation needs a user ID that
	// doesn't exist yet), so requireGrantSetNoSoDViolation instead evaluates
	// whether the FULL set of role grants landing atomically below would together
	// complete a policy — the same evasion this closes for an existing user's
	// individual grants, applied to "many roles minted for one brand-new user in
	// one call" instead.
	roleIDs := make([]uint, 0, len(grants))
	for _, g := range grants {
		roleIDs = append(roleIDs, g.RoleID)
	}
	if err := c.requireGrantSetNoSoDViolation(ctx, roleIDs); err != nil {
		return nil, err
	}

	created, err := c.storage.CreateUserWithRoleGrants(ctx, user, grants)
	if err != nil {
		// #117: same race/translation as CreateUser above — see its comment.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Best-effort password-history seed, after the atomic create (ADR-025).
	if c.passwordPolicy.HistoryCount > 0 {
		_ = c.storage.AddPasswordHistory(ctx, created.ID, hash, c.now())
	}

	return created, nil
}

// addRoleGrant deduplicates and appends a role grant. It is a package-level helper
// rather than a closure so it does not increase cognitive complexity of callers.
func addRoleGrant(grants *[]storage.RoleGrant, seen map[[2]uint]bool, roleID, projectID uint) {
	key := [2]uint{roleID, projectID}
	if seen[key] {
		return
	}
	seen[key] = true
	*grants = append(*grants, storage.RoleGrant{RoleID: roleID, Scope: storage.Scope{ProjectID: projectID}})
}

// resolveProjectRoleGrant validates and resolves a single ProjectAssignment into a
// storage.RoleGrant, enforcing the same authority-ceiling check as InviteGlobal.
func (c *KeyorixCore) resolveProjectRoleGrant(ctx context.Context, actorID uint, a ProjectAssignment) (storage.RoleGrant, error) {
	if a.ProjectID == 0 || a.Role == "" {
		return storage.RoleGrant{}, fmt.Errorf("%s: each project assignment needs a project_id and a role", i18n.T("ErrorValidation", nil))
	}
	if _, err := c.storage.GetProject(ctx, a.ProjectID); err != nil {
		return storage.RoleGrant{}, fmt.Errorf("%s: unknown project %d", i18n.T("ErrorValidation", nil), a.ProjectID)
	}
	r, err := c.storage.GetRoleByName(ctx, a.Role)
	if err != nil {
		return storage.RoleGrant{}, fmt.Errorf("%s: unknown role %q", i18n.T("ErrorValidation", nil), a.Role)
	}
	if err := c.requireAuthorityForRole(ctx, actorID, a.ProjectID, a.Role); err != nil {
		return storage.RoleGrant{}, err
	}
	return storage.RoleGrant{RoleID: r.ID, Scope: storage.Scope{ProjectID: a.ProjectID}}, nil
}

// ValidateRoleGrantAuthority checks that actorID has the authority to grant
// every role in grants and that the resulting grant set as a whole would not
// itself complete a separation-of-duties violation — the same two guards
// (requireAuthorityForRole per grant, requireGrantSetNoSoDViolation over the
// full set) CreateUserWithAssignments above applies to a human-supplied
// []ProjectAssignment. Exposed for a caller that already has a resolved
// []storage.RoleGrant instead of role names — namely
// CreateUserWithRoleGrantsProxy (server/http/handlers/misc_remote_proxy.go),
// which persists a RemoteStorage node's already-built grant set atomically
// and, unlike the human-facing path, never has a plaintext password or role
// names to work with, only role IDs. Kept in core rather than duplicated in
// the handler so the ceiling+SoD logic is defined exactly once (#G79).
func (c *KeyorixCore) ValidateRoleGrantAuthority(ctx context.Context, actorID uint, grants []storage.RoleGrant) error {
	if len(grants) > maxUserCreateAssignments {
		return fmt.Errorf("%s: grants exceeds the maximum batch size of %d", i18n.T("ErrorValidation", nil), maxUserCreateAssignments)
	}
	roleIDs := make([]uint, 0, len(grants))
	for _, g := range grants {
		role, err := c.storage.GetRole(ctx, g.RoleID)
		if err != nil {
			return fmt.Errorf("%s: unknown role id %d", i18n.T("ErrorValidation", nil), g.RoleID)
		}
		if err := c.requireAuthorityForRole(ctx, actorID, g.Scope.ProjectID, role.Name); err != nil {
			return err
		}
		roleIDs = append(roleIDs, g.RoleID)
	}
	return c.requireGrantSetNoSoDViolation(ctx, roleIDs)
}

// GetUser retrieves a user by ID.
func (c *KeyorixCore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// UpdateUser updates an existing user.
func (c *KeyorixCore) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*models.User, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if err := c.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	user, err := c.storage.GetUser(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if req.Username != "" && req.Username != user.Username {
		if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, fmt.Errorf("%w: username already exists", ErrUserAlreadyExists)
		} else if !storage.IsUserNotFound(err) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Username = req.Username
	}
	if req.Email != "" && req.Email != user.Email {
		existing, err := c.storage.GetUserByEmail(ctx, req.Email)
		if err == nil && existing != nil && existing.ID != user.ID {
			return nil, fmt.Errorf("%w: user with email already exists", ErrUserAlreadyExists)
		}
		if err != nil && !storage.IsUserNotFound(err) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	wasActive := user.IsActive
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	deactivating := wasActive && !user.IsActive
	user.UpdatedAt = c.now()

	var sessionHashes []string
	if deactivating {
		// Collect session hashes before the write so we can evict the auth cache
		// after commit. The HTTP auth middleware caches validated tokens for up to
		// validTokenTTL (30s); without eviction a just-deactivated user's session
		// keeps passing auth for that window — same race SetAccountState already
		// handles on suspend/deactivate via the account-state path (#r124).
		sessionHashes, _ = c.storage.ListSessionTokenHashesForUser(ctx, req.ID)
	}

	var patHashes []string
	var updated *models.User
	switch {
	case deactivating:
		// req.IsActive != nil is implied here (deactivating can only be true if
		// the request actually mutated user.IsActive from wasActive), so the
		// final persist must go through the conditional write — a plain
		// c.storage.UpdateUser here would silently clobber (or be clobbered by)
		// a concurrent IsActive flip on the same user with no error to either
		// caller (see UpdateUserIfActiveStateMatches's doc, storage/interface.go).
		//
		// #1646: the last-admin guard check (moved here, from before this switch)
		// and the deactivating write below must be serialized under the SAME lock
		// acquisition, across every replica of an HA deployment — two concurrent
		// UpdateUser deactivations of two DIFFERENT admins could otherwise each
		// observe "another admin survives" and both proceed, jointly stranding the
		// install with zero admins. See lastAdminGuardLockKey's doc comment
		// (account_state.go).
		err = c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
			if err := c.guardLastAdminDeactivation(ctx, req.ID); err != nil {
				return err
			}
			return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
				matched, terr := tx.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
				if terr != nil {
					return terr
				}
				if !matched {
					return fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
				}
				updated = user
				var patErr, sessionErr error
				var hashes []string
				hashes, patErr = tx.RevokeAllPersonalAccessTokensForUser(ctx, req.ID)
				if patErr == nil {
					patHashes = hashes
				}
				sessionErr = tx.DeleteSessionsForUserExcept(ctx, req.ID, 0)
				// Best-effort, not fatal: the conditional write this switch case
				// exists for (UpdateUserIfActiveStateMatches) has ALREADY matched
				// and applied by this point -- the deactivation itself durably
				// succeeded. Letting a revocation failure here fail the whole
				// WithTransaction call would report total failure for an
				// operation that, from the target user's perspective, already
				// happened. This matters most over storage.type: remote, where
				// WithTransaction provides NO real atomicity at all (each
				// sub-call is its own independent HTTP round-trip -- see
				// remote_transaction.go) -- treating this as fatal there could
				// never have rolled the deactivation back anyway, only hidden
				// that it succeeded behind a misleading error.
				//
				// Safe specifically because a failed revocation does NOT leave a
				// working credential: ValidateSessionToken (auth.go) and
				// ValidatePATToken (pat.go) BOTH independently re-check the live
				// user.IsActive/AccountLoginBlocked state on every single use of
				// a session or PAT, cold path AND the 30s warm auth-cache path
				// (via AccountStillUsable, server/middleware/auth.go's
				// serveAuthCacheHit) -- already-committed IsActive=false alone
				// blocks the credential regardless of whether its row was ever
				// deleted. There is no session-expiry sweeper in this codebase
				// (CleanupExpiredSessions is implemented but never scheduled), so
				// a row a failed revocation leaves behind lingers indefinitely --
				// but inertly: it authorizes nothing. The residual cost is
				// orphaned-row hygiene and forensic noise, not a live credential,
				// which is why this is audited (right below) rather than merely
				// swallowed.
				if patErr != nil || sessionErr != nil {
					// nil actor: UpdateUser (unlike DeleteUser/SetAccountState) takes
					// no actorID parameter at all -- a pre-existing gap in this
					// function's own signature, not something this fix should
					// silently paper over with a fabricated attribution.
					c.writeAuditEventFailed(ctx, EventUserDeactivationCleanupFailed, nil, nil, "",
						fmt.Sprintf("user %d deactivated, but credential cleanup was incomplete (pat_error=%v, session_error=%v) -- "+
							"the account is already login-blocked regardless, but a stale row may remain until its own expiry",
							req.ID, patErr, sessionErr))
				}
				return nil
			})
		})
	case req.IsActive != nil:
		// Not deactivating (either re-activating, or a redundant "set to the same
		// value" call) but the request still explicitly asserts IsActive — same
		// TOCTOU exposure as the deactivating branch above, just without the
		// session/PAT revocation side effects.
		var matched bool
		matched, err = c.storage.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
		if err == nil {
			if !matched {
				err = fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
			} else {
				updated = user
			}
		}
	default:
		// No active-state assertion in this request, but a plain c.storage.UpdateUser
		// (unconditional Save) is still a check-then-act race against any concurrent
		// IsActive flip observed between the GetUser above and this write — same
		// TOCTOU shape as the two branches above, just asserting the unchanged
		// wasActive value as the precondition instead of a new one.
		var matched bool
		matched, err = c.storage.UpdateUserIfActiveStateMatches(ctx, user, wasActive)
		if err == nil {
			if !matched {
				err = fmt.Errorf("user %d: %w", req.ID, ErrUserActiveStateConflict)
			} else {
				updated = user
			}
		}
	}
	if err != nil {
		if errors.Is(err, ErrUserActiveStateConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if deactivating {
		c.invalidateTokenCache(sessionHashes...)
		c.invalidateTokenCache(patHashes...)
	}
	return updated, nil
}

// EventUserDeleted/EventUserRestored are audited on the admin delete/restore path
// (distinct from SCIM's own scim.user_deprovisioned/scim.user_reactivated events).
const (
	EventUserDeleted  = "user.deleted"
	EventUserRestored = "user.restored"
)

// EventUserDeactivationCleanupFailed is audited (Success=false) when
// UpdateUser's deactivating branch's PAT/session revocation is incomplete —
// see that branch's own comment for why this is best-effort rather than
// fatal to the deactivation itself, and why a failure here doesn't leave a
// working credential (ValidateSessionToken/ValidatePATToken's live
// user.IsActive/AccountLoginBlocked re-check already blocks it). This event
// exists purely for discoverability: with no session-expiry sweeper in this
// codebase, a row a failed revocation leaves behind is inert but otherwise
// invisible until an operator goes looking for it.
const EventUserDeactivationCleanupFailed = "user.deactivation_cleanup_failed"

// DeleteUser deprovisions and soft-deletes a user by ID: blocks login
// (AccountDeprovisioned, mirroring DeprovisionSCIMUser), terminates every session,
// revokes every personal access token, and evicts them from the auth cache — then
// soft-deletes the record. Before this, only the row was soft-deleted: IsActive and
// AccountState were untouched and no session/PAT was revoked, leaving live
// credentials usable for up to the auth-cache TTL and, since nothing was actually
// revoked, indefinitely if the account was later restored (see RestoreUser).
// Refuses to deprovision the install's last global administrator
// (guardLastAdminDeactivation), same as SCIM DELETE. actorID is the acting admin
// (for the audit trail; 0 = no actor known, e.g. an unauthenticated internal caller
// — the audit event's UserID is then left nil rather than pointing at a nonexistent
// actor).
func (c *KeyorixCore) DeleteUser(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	// #1646: guardLastAdminDeactivation's read and the deactivating write below
	// must be serialized under the SAME lock acquisition, across every replica of
	// an HA deployment, not just within this process — previously
	// accountStateMu (an in-process sync.Mutex) alone let two concurrent DeleteUser
	// calls for two different admins each observe "not the last admin" and both
	// proceed on two different replicas, jointly stranding the install with zero
	// admins. See lastAdminGuardLockKey's doc comment (account_state.go).
	return c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
		if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
			return err
		}
		user.IsActive = false
		if NormalizeAccountState(user.AccountState) != AccountSuspended {
			user.AccountState = AccountDeprovisioned
		}
		user.UpdatedAt = c.now()
		sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, id)
		var patHashes []string
		if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
			if _, err := tx.UpdateUser(ctx, user); err != nil {
				return err
			}
			if err := tx.DeleteSessionsForUserExcept(ctx, id, 0); err != nil {
				return err
			}
			hashes, err := tx.RevokeAllPersonalAccessTokensForUser(ctx, id)
			if err != nil {
				return err
			}
			patHashes = hashes
			return tx.DeleteUser(ctx, id)
		}); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		c.invalidateTokenCache(sessionHashes...)
		c.invalidateTokenCache(patHashes...)
		c.writeAuditEvent(ctx, EventUserDeleted, actorPtr(actorID), nil,
			fmt.Sprintf("deleted user %d (%s)", id, user.Username))
		return nil
	})
}

// EventUserCredentialsRevoked is audited when an admin-driven bulk PAT/session
// revocation runs against a target user via RevokeAllPersonalAccessTokensForUser
// or DeleteSessionsForUserExcept below (the /system proxy layer's direct-caller
// path — server/http/handlers/users_credentials_proxy.go). #1530: for a
// node-credential caller these primitives are still reached via the raw
// storage passthrough with no audit event at all (the same node-relay
// actor-attribution gap #1530 tracks for the sibling /system proxies) — this
// event only covers the direct-caller half fixed here.
const EventUserCredentialsRevoked = "user.credentials_revoked"

// requireUserCredentialsRevokeAuthority is the shared ceiling for
// RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept below.
//
// Derived, not chosen: core.UpdateUser and core.DeleteUser perform NO
// caller-authority check of their own on a deactivating transition (only
// guardLastAdminDeactivation, a target-state invariant with no actor
// parameter — see its doc in scim.go) — authority is enforced entirely by the
// HTTP layer, at RequirePermission(permUsersWrite) on PUT /api/v1/users/{id}
// (server/http/router.go) and identically on POST /api/v1/users/{id}/suspend.
// "users.write" at GLOBAL scope is therefore the actual ceiling that governs
// "who may deactivate a user" today. Revoking a user's live PATs/sessions is a
// sub-operation of that same action (core.UpdateUser's own deactivating
// branch already does both under a real local transaction — see
// UpdateUser/DeleteUser above), so it inherits that SAME ceiling here rather
// than the broader, differently-scoped system.write the /system route group
// otherwise blanket-gates on: looser would reopen exactly the bypass shape
// #1552 was filed for; stricter would refuse a caller the operation it
// belongs to already permits.
func (c *KeyorixCore) requireUserCredentialsRevokeAuthority(ctx context.Context, actorType string, actorID uint) error {
	allowed, err := c.AuthorizePrincipal(ctx, actorType, actorID, permUsersWrite, Scope{})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !allowed {
		return fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "revoking a user's credentials requires users.write authority")
	}
	return nil
}

// RevokeAllPersonalAccessTokensForUser authorizes, performs, and audits an
// admin-driven bulk PAT revocation for targetUserID — the /system proxy
// layer's direct-caller entry point (RevokeAllPersonalAccessTokensForUserProxy).
// See requireUserCredentialsRevokeAuthority for the ceiling this enforces.
func (c *KeyorixCore) RevokeAllPersonalAccessTokensForUser(ctx context.Context, actorType string, actorID, targetUserID uint) ([]string, error) {
	if err := c.requireUserCredentialsRevokeAuthority(ctx, actorType, actorID); err != nil {
		return nil, err
	}
	hashes, err := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	c.invalidateTokenCache(hashes...)
	c.writeAuditEvent(ctx, EventUserCredentialsRevoked, actorPtr(actorID), nil,
		fmt.Sprintf("revoked all personal access tokens for user %d", targetUserID))
	return hashes, nil
}

// DeleteSessionsForUserExcept authorizes, performs, and audits an admin-driven
// session termination for targetUserID (keeping exceptSessionID, if nonzero) —
// the /system proxy layer's direct-caller entry point
// (DeleteSessionsForUserExceptProxy). See requireUserCredentialsRevokeAuthority
// for the ceiling this enforces.
func (c *KeyorixCore) DeleteSessionsForUserExcept(ctx context.Context, actorType string, actorID, targetUserID, exceptSessionID uint) error {
	if err := c.requireUserCredentialsRevokeAuthority(ctx, actorType, actorID); err != nil {
		return err
	}
	sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, targetUserID)
	if err := c.storage.DeleteSessionsForUserExcept(ctx, targetUserID, exceptSessionID); err != nil {
		return err
	}
	c.invalidateTokenCache(sessionHashes...)
	c.writeAuditEvent(ctx, EventUserCredentialsRevoked, actorPtr(actorID), nil,
		fmt.Sprintf("deleted sessions for user %d", targetUserID))
	return nil
}

// RestoreUser clears the deleted_at timestamp on a soft-deleted user and forces
// re-credentialing: the account comes back requiring a password reset rather than
// silently reactivating, since DeleteUser's revoked sessions/PATs are gone for good
// (hard-deleted/permanently revoked, not merely soft-deleted) and the old password
// may be stale after an offboarding. actorID is the acting admin (audit trail).
func (c *KeyorixCore) RestoreUser(ctx context.Context, actorID, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if err := c.storage.RestoreUser(ctx, id); err != nil {
		if storage.IsUserNotFound(err) {
			return fmt.Errorf("%s: user not found or not deleted", i18n.T("ErrorUserNotFound", nil))
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	user.IsActive = true
	user.AccountState = AccountPasswordResetRequired
	user.UpdatedAt = c.now()
	if _, err := c.storage.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventUserRestored, actorPtr(actorID), nil,
		fmt.Sprintf("restored user %d (%s); password reset required", id, user.Username))
	return nil
}

// ListUsers lists users with filtering and pagination.
func (c *KeyorixCore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if filter == nil {
		filter = &storage.UserFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	users, total, err := c.storage.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserByEmail retrieves a user by email address.
func (c *KeyorixCore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "email is required")
	}
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username. Backs the GET
// /api/v1/users/by-username HTTP route (#505) — the server-side counterpart
// RemoteStorage.GetUserByUsername needs.
func (c *KeyorixCore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if username == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "username is required")
	}
	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// GetUserByExternalID retrieves a user by the IdP-assigned external id. Backs the
// GET /api/v1/users/by-external-id HTTP route (#505) — the server-side
// counterpart RemoteStorage.GetUserByExternalID needs for SSO/SCIM identity
// resolution.
func (c *KeyorixCore) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	if externalID == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "external_id is required")
	}
	user, err := c.storage.GetUserByExternalID(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// ── Validation ────────────────────────────────────────────────────────────────

func (c *KeyorixCore) validateCreateUserRequest(req *CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("%s", i18n.T("LabelUsername", nil))
	}
	if err := validateUsernameFormat(req.Username); err != nil {
		return err
	}
	if req.Email == "" {
		return fmt.Errorf("%s", i18n.T("LabelEmail", nil))
	}
	if err := validateEmailFormat(req.Email); err != nil {
		return err
	}
	// DisplayName is optional at this layer (buildUserForCreate defaults it to
	// Username when blank) — only format-check it when the caller actually
	// supplied one, matching the HTTP path's required-at-the-request-body-level
	// semantics without re-imposing that requirement here.
	if req.DisplayName != "" {
		if err := validateDisplayNameFormat(req.DisplayName); err != nil {
			return err
		}
	}
	if req.Password == "" {
		return fmt.Errorf("%s", i18n.T("LabelPassword", nil))
	}
	return nil
}

func (c *KeyorixCore) validateUpdateUserRequest(req *UpdateUserRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("user ID is required")
	}
	// Username/Email/DisplayName are partial-update fields (UpdateUser only
	// applies a non-empty value; see the req.Username != "" / req.Email != "" /
	// req.DisplayName != "" guards below in UpdateUser) — an empty string means
	// "leave unchanged," not "clear the field," so only format-check a value
	// the caller actually supplied (G38: gRPC/CLI-embedded previously skipped
	// this check entirely, unlike the HTTP path's `omitempty,...` request-body
	// validate tags).
	if req.Username != "" {
		if err := validateUsernameFormat(req.Username); err != nil {
			return err
		}
	}
	if req.Email != "" {
		if err := validateEmailFormat(req.Email); err != nil {
			return err
		}
	}
	if req.DisplayName != "" {
		if err := validateDisplayNameFormat(req.DisplayName); err != nil {
			return err
		}
	}
	return nil
}
