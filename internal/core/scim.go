// scim.go — SCIM 2.0 user provisioning (RFC 7644). An IdP (Okta/Entra) provisions,
// updates, deactivates, and deletes Keyorix users over /scim/v2 (see the SCIM
// handler + the static-token middleware). A SCIM userName is typically an email/UPN,
// which Keyorix usernames (alphanumeric) cannot hold verbatim, so a compliant
// username is DERIVED from the userName and the IdP's stable externalId is stored
// for reconciliation. Provisioned users have no usable password (a random,
// discarded one) — they authenticate via SSO or set a password out-of-band — and
// start in pending_first_login (or suspended when provisioned inactive).
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	EventSCIMUserProvisioned   = "scim.user_provisioned"
	EventSCIMUserUpdated       = "scim.user_updated"
	EventSCIMUserDeprovisioned = "scim.user_deprovisioned"
)

var scimNonAlphanum = regexp.MustCompile(`[^a-z0-9]`)

// deriveSCIMUsername builds a unique alphanumeric username from a SCIM userName
// (typically an email/UPN): its local-part, lowercased and stripped to [a-z0-9],
// padded to the 3-char minimum, with a numeric suffix on collision.
func (c *KeyorixCore) deriveSCIMUsername(ctx context.Context, userName string) (string, error) {
	base := userName
	if i := strings.IndexByte(base, '@'); i > 0 {
		base = base[:i]
	}
	base = scimNonAlphanum.ReplaceAllString(strings.ToLower(base), "")
	if len(base) < 3 {
		base += "usr"
	}
	if len(base) > 40 {
		base = base[:40]
	}
	notFound := i18n.T("ErrorUserNotFound", nil)
	for i := 0; i < 1000; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s%d", base, i)
		}
		_, err := c.storage.GetUserByUsername(ctx, candidate)
		if err == nil {
			continue // taken — try the next suffix
		}
		if strings.Contains(err.Error(), notFound) {
			return candidate, nil // available
		}
		return "", err // a real lookup error
	}
	return "", fmt.Errorf("could not derive a unique username from %q", userName)
}

// randomPasswordHash mints a bcrypt hash of a random, discarded password so a
// provisioned account has no usable password until the user sets one.
func randomPasswordHash() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(b)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// FindSCIMUser resolves a provisioned user by externalId first, then by email
// (SCIM userName). Returns (nil, nil) when neither matches — used by the handler to
// implement userName-filter reconciliation.
func (c *KeyorixCore) FindSCIMUser(ctx context.Context, externalID, email string) (*models.User, error) {
	notFound := i18n.T("ErrorUserNotFound", nil)
	if externalID != "" {
		if u, err := c.storage.GetUserByExternalID(ctx, externalID); err == nil {
			return u, nil
		} else if !strings.Contains(err.Error(), notFound) {
			return nil, err
		}
	}
	if email != "" {
		if u, err := c.storage.GetUserByEmail(ctx, email); err == nil {
			return u, nil
		} else if !strings.Contains(err.Error(), notFound) {
			return nil, err
		}
	}
	return nil, nil
}

// ProvisionSCIMUser creates a Keyorix user from a SCIM Create request. actorID is
// the SCIM principal (0 for the provisioner). It refuses a duplicate externalId or
// email.
func (c *KeyorixCore) ProvisionSCIMUser(ctx context.Context, actorID uint, userName, displayName, email, externalID string, active bool) (*models.User, error) {
	if userName == "" {
		return nil, fmt.Errorf("userName is required")
	}
	if email == "" {
		email = userName // SCIM userName is conventionally the email
	}
	// Fail CLOSED on a lookup error: swallowing it would let a transient DB error during
	// the dedup check fall through to CreateUser and mint a SECOND identity with the same
	// email (there is no DB-level email uniqueness), and SSO/SCIM resolve email via
	// first-match — so which physical account a login binds to would become ambiguous.
	existing, ferr := c.FindSCIMUser(ctx, externalID, email)
	if ferr != nil {
		return nil, fmt.Errorf("failed to check for an existing user: %w", ferr)
	}
	if existing != nil {
		return nil, fmt.Errorf("a user already exists for this externalId/email")
	}
	username, err := c.deriveSCIMUsername(ctx, userName)
	if err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = userName
	}
	hash, err := randomPasswordHash()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	now := c.now()
	state := AccountPendingFirstLogin
	if !active {
		state = AccountDeprovisioned
	}
	created, err := c.storage.CreateUser(ctx, &models.User{
		Username: username, Email: email, DisplayName: displayName,
		PasswordHash: hash, IsActive: active, AccountState: state, ExternalID: externalID,
		PasswordChangedAt: &now, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Minimal install-wide baseline role (ADR-021), best-effort.
	if role, rerr := c.storage.GetRoleByName(ctx, "system_viewer"); rerr == nil {
		_ = c.storage.AssignRole(ctx, created.ID, role.ID, Scope{})
	}
	c.writeAuditEvent(ctx, EventSCIMUserProvisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM provisioned user %d (username=%s, externalId=%q, active=%t)", created.ID, username, externalID, active))
	return created, nil
}

// scimManaged reports whether user was provisioned/adopted via SCIM (carries a
// stored externalId — only ProvisionSCIMUser sets one; a native/local account never
// does). UpdateSCIMUser and DeprovisionSCIMUser refuse to operate on an id that
// isn't: the SCIM PUT/PATCH/DELETE endpoints take an arbitrary numeric id straight
// off the URL path with no check that it belongs to an account SCIM actually owns,
// so a valid (e.g. provisioning-only) SCIM bearer token could otherwise rewrite a
// NATIVE admin's email to a fresh attacker-controlled address (the existing
// same-email-collision guard only blocks an address already in use) and then claim
// the account via SSO/SAML email-fallback resolution — an account takeover reachable
// with no admin-console access at all (#120).
func scimManaged(user *models.User) bool {
	return user.ExternalID != ""
}

// UpdateSCIMUser applies a SCIM Replace/PATCH to a user: displayName, email, and the
// active flag. Deactivation marks the account deprovisioned (blocks login, terminates
// sessions); activation clears only a prior SCIM deactivation. An admin security
// suspension is sticky and survives IdP sync — only an admin can clear it
// (ReactivateUser), so routine SCIM traffic can't undo an incident-response lockout.
// nil fields are left unchanged. Refuses a target that isn't SCIM-managed (scimManaged).
func (c *KeyorixCore) UpdateSCIMUser(ctx context.Context, actorID, id uint, displayName, email *string, active *bool) (*models.User, error) {
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if !scimManaged(user) {
		return nil, fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
	}
	if displayName != nil {
		user.DisplayName = *displayName
	}
	if email != nil && *email != "" {
		// Refuse an email that collides with a DIFFERENT user. SCIM email is trusted by
		// identity resolution (SSO matches by email), so silently overwriting a low-priv
		// account's email to an admin's would corrupt the email→account mapping and
		// enable account linking/takeover. The create path already guards this.
		if existing, eerr := c.storage.GetUserByEmail(ctx, *email); eerr == nil && existing != nil && existing.ID != user.ID {
			return nil, fmt.Errorf("%s: email already in use by another user", i18n.T("ErrorValidation", nil))
		}
		user.Email = *email
	}
	deactivated := false
	if active != nil {
		if !*active {
			// Don't let a routine (or hostile) SCIM sync deactivate the only admin.
			if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
				return nil, err
			}
		}
		user.IsActive = *active
		if *active {
			// Reactivation clears only a SCIM/IdP deactivation. An admin security
			// suspension (AccountSuspended) is sticky: routine IdP sync, which re-sends
			// active=true for every active user, must not undo an incident-response
			// lockout — only an admin clears that, via ReactivateUser.
			if NormalizeAccountState(user.AccountState) == AccountDeprovisioned {
				user.AccountState = AccountActive
			}
		} else {
			// Mark the SCIM/IdP deactivation distinctly so a later reactivation can tell
			// it from an admin-set state. Only an 'active' account moves to deprovisioned:
			// any admin-set state (suspended, AND the restricted password_reset_required /
			// pending_first_login states) is preserved, so a routine IdP deactivate→
			// reactivate cycle cannot silently clear a forced-credential-reset or a
			// first-login requirement. Login is blocked meanwhile by IsActive=false
			// (set above) regardless of which state is retained.
			if NormalizeAccountState(user.AccountState) == AccountActive {
				user.AccountState = AccountDeprovisioned
			}
			deactivated = true
		}
	}
	user.UpdatedAt = c.now()
	updated, err := c.storage.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if deactivated {
		// Suspension must be effective immediately, not lingering until tokens expire —
		// terminate sessions AND evict them from the auth cache (the fast path bypasses the
		// DB, so without eviction an offboarded user keeps access for the cache TTL).
		_ = c.deleteSessionsForUserAndEvict(ctx, id, 0, "")
	}
	c.writeAuditEvent(ctx, EventSCIMUserUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM updated user %d", id))
	return updated, nil
}

// guardLastAdminDeactivation refuses an operation that would deactivate/deprovision the
// only remaining install administrator, so a routine or hostile SCIM push can't lock
// everyone out. Mirrors guardLastGlobalAdmin's assignment scan but keyed on the target.
func (c *KeyorixCore) guardLastAdminDeactivation(ctx context.Context, targetID uint) error {
	isAdmin, err := c.IsGlobalAdmin(ctx, targetID)
	if err != nil || !isAdmin {
		return nil // not an admin (or can't tell) — not the last-admin case
	}
	adminIDs := c.installAdminRoleIDSet(ctx)
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, a := range assignments {
		if !adminIDs[a.RoleID] {
			continue
		}
		// Any OTHER global-admin grant (a different user, or a group) means governance
		// survives the target's removal.
		if a.PrincipalType == "user" && a.PrincipalID == targetID {
			continue
		}
		return nil
	}
	return fmt.Errorf("refusing to deactivate the last install administrator via SCIM")
}

// DeprovisionSCIMUser handles a SCIM DELETE: it deprovisions the user (blocks login,
// terminates sessions) and soft-deletes the record, so the account is recoverable
// within the retention window rather than hard-destroyed. Refuses a target that
// isn't SCIM-managed (scimManaged) — a valid SCIM token must not be able to
// deprovision an arbitrary native account it never provisioned.
func (c *KeyorixCore) DeprovisionSCIMUser(ctx context.Context, actorID, id uint) error {
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if !scimManaged(user) {
		return fmt.Errorf("%s: not a SCIM-managed account", i18n.T("ErrorUserNotFound", nil))
	}
	// Don't let a SCIM DELETE deprovision the only admin and lock the install out.
	if err := c.guardLastAdminDeactivation(ctx, id); err != nil {
		return err
	}
	user.IsActive = false
	// Mark as SCIM-deprovisioned rather than admin-suspended, but never downgrade an
	// existing admin security suspension. The user is soft-deleted below regardless,
	// so this only affects the state on the recoverable record.
	if NormalizeAccountState(user.AccountState) != AccountSuspended {
		user.AccountState = AccountDeprovisioned
	}
	user.UpdatedAt = c.now()
	// Capture the user's session-token hashes BEFORE the transaction so they can be
	// evicted from the auth cache after commit (the stored token is the SHA-256 cache key).
	sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, id)
	// Suspend + terminate sessions + soft-delete atomically: a SCIM DELETE either fully
	// deprovisions or leaves the account untouched, so a mid-way storage failure can't
	// leave it half-deprovisioned (suspended but not deleted), which would make retries
	// non-idempotent.
	if err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.UpdateUser(ctx, user); err != nil {
			return err
		}
		_ = tx.DeleteSessionsForUserExcept(ctx, id, 0)
		return tx.DeleteUser(ctx, id)
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	// Evict the terminated sessions from the auth cache AFTER commit, so a deprovisioned
	// (offboarded) user's live session stops authenticating immediately instead of
	// lingering for the cache TTL.
	c.invalidateTokenCache(sessionHashes...)
	c.writeAuditEvent(ctx, EventSCIMUserDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned user %d (%s)", id, user.Username))
	return nil
}

// SCIMMaxPageSize bounds how many resources a single SCIM list page returns — the
// value advertised in ServiceProviderConfig (filter.maxResults). A larger requested
// count is clamped to it so an unfiltered list can't drain the whole directory into one
// response (memory + DB amplification).
const SCIMMaxPageSize = 200

// ListSCIMUsersPage returns one page of users for a SCIM list and the total count.
// startIndex is 1-based (SCIM convention); count is clamped to [0, SCIMMaxPageSize]
// (count==0 returns no resources, just the total).
func (c *KeyorixCore) ListSCIMUsersPage(ctx context.Context, startIndex, count int) ([]*models.User, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > SCIMMaxPageSize {
		count = SCIMMaxPageSize
	}
	if count == 0 {
		// SCIM count=0 → return totalResults only. Use PageSize=1 to get an accurate
		// total without a separate count API; the single fetched row is discarded.
		_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return []*models.User{}, int(total), nil
	}
	users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Offset: startIndex - 1, PageSize: count})
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, int(total), nil
}

// ListSCIMUsers returns users for a SCIM list, paging through all of them.
func (c *KeyorixCore) ListSCIMUsers(ctx context.Context) ([]*models.User, error) {
	const pageSize = 200
	var out []*models.User
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		out = append(out, users...)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	return out, nil
}
