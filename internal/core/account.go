// account.go — Self-service account operations for the authenticated user.
//
// These power the "My Account" page (ADR-021) and are deliberately scoped to the
// caller's own user ID: the HTTP layer never forwards a target user ID, role, or
// active flag from the request body. For admin user management see users.go.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// UpdateOwnProfile updates the caller's display name and email only. It delegates
// to UpdateUser (which enforces email uniqueness) but constructs the request from
// the authenticated userID, so a caller can never change username/is_active or
// target another user.
func (c *KeyorixCore) UpdateOwnProfile(ctx context.Context, userID uint, displayName, email string) (*models.User, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.UpdateUser(ctx, &UpdateUserRequest{
		ID:          userID,
		DisplayName: displayName,
		Email:       email,
	})
}

// ChangePassword verifies the caller's current password and sets a new one. On
// success it drops the caller's other sessions (keeping the one identified by
// keepSessionToken) so a credential change invalidates other devices. If the
// current session cannot be resolved from keepSessionToken (e.g. a PAT-authenticated
// request), all of the user's sessions are dropped.
func (c *KeyorixCore) ChangePassword(ctx context.Context, userID uint, current, newPassword, keepSessionToken string) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)); err != nil {
		return fmt.Errorf("%s: current password is incorrect", i18n.T("ErrorValidation", nil))
	}
	// Enforce the configured password policy (ADR-025). Done after the
	// current-password check so an attacker can't probe the policy without
	// already holding valid credentials.
	if err := c.passwordPolicy.Validate(newPassword, user); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	user.PasswordHash = string(hash)
	user.UpdatedAt = c.now()
	if _, err := c.storage.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Drop other sessions. Best-effort: the password change itself has succeeded.
	var keepID uint
	if keepSessionToken != "" {
		if s, serr := c.storage.GetSession(ctx, keepSessionToken); serr == nil {
			keepID = s.ID
		}
	}
	_ = c.storage.DeleteSessionsForUserExcept(ctx, userID, keepID)
	return nil
}

// CurrentSessionID returns the session ID backing a session token, or 0 if the
// token is not a session (e.g. a PAT) or no longer exists. Used to flag the
// "current" row in the active-sessions list.
func (c *KeyorixCore) CurrentSessionID(ctx context.Context, token string) uint {
	if token == "" {
		return 0
	}
	s, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0
	}
	return s.ID
}

// ListOwnSessions returns the caller's active sessions.
func (c *KeyorixCore) ListOwnSessions(ctx context.Context, userID uint) ([]*models.Session, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListSessionsByUser(ctx, userID)
}

// RevokeOwnSession deletes one of the caller's sessions after verifying ownership.
// A session that exists but belongs to another user is reported as not found, so a
// caller cannot probe for or revoke other users' session IDs.
func (c *KeyorixCore) RevokeOwnSession(ctx context.Context, userID, sessionID uint) error {
	if userID == 0 || sessionID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and session IDs are required")
	}
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil || session.UserID != userID {
		return fmt.Errorf("%s: session not found", i18n.T("ErrorNotFound", nil))
	}
	return c.storage.DeleteSession(ctx, sessionID)
}
