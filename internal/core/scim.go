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
	if existing, _ := c.FindSCIMUser(ctx, externalID, email); existing != nil {
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
		state = AccountSuspended
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

// UpdateSCIMUser applies a SCIM Replace/PATCH to a user: displayName, email, and the
// active flag (deactivation suspends the account and terminates sessions; activation
// returns it to active). nil fields are left unchanged.
func (c *KeyorixCore) UpdateSCIMUser(ctx context.Context, actorID, id uint, displayName, email *string, active *bool) (*models.User, error) {
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if displayName != nil {
		user.DisplayName = *displayName
	}
	if email != nil && *email != "" {
		user.Email = *email
	}
	deactivated := false
	if active != nil {
		user.IsActive = *active
		if *active {
			if AccountLoginBlocked(user.AccountState) {
				user.AccountState = AccountActive
			}
		} else {
			user.AccountState = AccountSuspended
			deactivated = true
		}
	}
	user.UpdatedAt = c.now()
	updated, err := c.storage.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if deactivated {
		// Suspension must be effective immediately, not lingering until tokens expire.
		_ = c.storage.DeleteSessionsForUserExcept(ctx, id, 0)
	}
	c.writeAuditEvent(ctx, EventSCIMUserUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM updated user %d", id))
	return updated, nil
}

// DeprovisionSCIMUser handles a SCIM DELETE: it suspends the user (blocks login,
// terminates sessions) and soft-deletes the record, so the account is recoverable
// within the retention window rather than hard-destroyed.
func (c *KeyorixCore) DeprovisionSCIMUser(ctx context.Context, actorID, id uint) error {
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	user.IsActive = false
	user.AccountState = AccountSuspended
	user.UpdatedAt = c.now()
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
	c.writeAuditEvent(ctx, EventSCIMUserDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned user %d (%s)", id, user.Username))
	return nil
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
