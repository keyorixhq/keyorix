// users.go — User CRUD, list, and validation.
//
// CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser, ListUsers, GetUserByEmail.
// For group operations see groups.go. Types are in users_types.go.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

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

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, "", fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
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
		return nil, "", fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
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
			return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
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
	user, hash, err := c.buildUserForCreate(ctx, req)
	if err != nil {
		return nil, err
	}

	// Resolve every grant before touching the database. Dedup by role+project so a
	// repeated assignment can't trip the unique constraint inside the transaction.
	grants := make([]storage.RoleGrant, 0, len(assignments)+1)
	seen := map[[2]uint]bool{}
	addGrant := func(roleID, projectID uint) {
		key := [2]uint{roleID, projectID}
		if seen[key] {
			return
		}
		seen[key] = true
		grants = append(grants, storage.RoleGrant{RoleID: roleID, Scope: storage.Scope{ProjectID: projectID}})
	}

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
	addGrant(sr.ID, 0)

	for _, a := range assignments {
		if a.ProjectID == 0 || a.Role == "" {
			return nil, fmt.Errorf("%s: each project assignment needs a project_id and a role", i18n.T("ErrorValidation", nil))
		}
		if _, err := c.storage.GetProject(ctx, a.ProjectID); err != nil {
			return nil, fmt.Errorf("%s: unknown project %d", i18n.T("ErrorValidation", nil), a.ProjectID)
		}
		r, err := c.storage.GetRoleByName(ctx, a.Role)
		if err != nil {
			return nil, fmt.Errorf("%s: unknown role %q", i18n.T("ErrorValidation", nil), a.Role)
		}
		// Same ceiling check InviteGlobal applies to each of its own project
		// assignments — without this, a non-admin roles.assign holder could bundle
		// an admin-conferring project assignment into an otherwise-innocuous create.
		if err := c.requireAuthorityForRole(ctx, actorID, a.ProjectID, a.Role); err != nil {
			return nil, err
		}
		addGrant(r.ID, a.ProjectID)
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
			return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Best-effort password-history seed, after the atomic create (ADR-025).
	if c.passwordPolicy.HistoryCount > 0 {
		_ = c.storage.AddPasswordHistory(ctx, created.ID, hash, c.now())
	}

	return created, nil
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
func (c *KeyorixCore) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*models.User, error) {
	if err := c.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	user, err := c.storage.GetUser(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if req.Username != "" && req.Username != user.Username {
		if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
		} else if err != nil && !storage.IsUserNotFound(err) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Username = req.Username
	}
	if req.Email != "" && req.Email != user.Email {
		existing, err := c.storage.GetUserByEmail(ctx, req.Email)
		if err == nil && existing != nil && existing.ID != user.ID {
			return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
		}
		if err != nil && !storage.IsUserNotFound(err) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	user.UpdatedAt = c.now()
	updated, err := c.storage.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updated, nil
}

// EventUserDeleted/EventUserRestored are audited on the admin delete/restore path
// (distinct from SCIM's own scim.user_deprovisioned/scim.user_reactivated events).
const (
	EventUserDeleted  = "user.deleted"
	EventUserRestored = "user.restored"
)

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

// ── Validation ────────────────────────────────────────────────────────────────

func (c *KeyorixCore) validateCreateUserRequest(req *CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("%s", i18n.T("LabelUsername", nil))
	}
	if req.Email == "" {
		return fmt.Errorf("%s", i18n.T("LabelEmail", nil))
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
	return nil
}
