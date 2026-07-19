// secret_acl.go — per-secret fine-grained access control (RBAC Phase 3).
//
// A SecretACL row grants a specific user one or more permissions on a single secret,
// independently of any project-level role they hold (or don't hold). This implements
// the Vault-path-style least-privilege model: a CI token can be granted secrets.read
// on exactly one secret without needing a project role at all.
//
// ACL grants are ADDITIVE: the user is allowed if EITHER a SecretACL entry covers the
// requested permission OR the project-scope RBAC check passes (see AuthorizeSecret in
// authz.go). ACL management itself (grant/revoke/list) requires secrets.manage at
// project scope, so only project admins can hand out per-secret grants.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Valid permission values for a SecretACL entry.
var validACLPermissions = []string{"secrets.read", "secrets.write"}

// Secret-ACL audit event types.
const (
	EventSecretACLGranted = "secret.acl_granted" // #nosec G101 -- audit event type, not a credential
	EventSecretACLRevoked = "secret.acl_revoked" // #nosec G101 -- audit event type, not a credential
)

// EncodeSecretACLPerms JSON-encodes a permission list for storage.
func EncodeSecretACLPerms(perms []string) (string, error) {
	if len(perms) == 0 {
		return "", fmt.Errorf("%s: at least one permission is required", i18n.T("ErrorValidation", nil))
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeSecretACLPerms parses a stored permissions column back into a slice.
// An empty or invalid column yields nil.
func DecodeSecretACLPerms(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// GrantSecretACL creates or updates a SecretACL grant for (secretID, userID).
// actorID is the admin performing the grant. perms must be a non-empty subset
// of validACLPermissions. Requires secrets.manage at the secret's project scope
// (enforced at the HTTP layer). Emits a secret.acl_granted audit event.
func (c *KeyorixCore) GrantSecretACL(ctx context.Context, actorID, secretID, userID uint, perms []string) error {
	if actorID == 0 {
		return fmt.Errorf("%s: actor ID is required", i18n.T("ErrorValidation", nil))
	}
	if secretID == 0 {
		return fmt.Errorf("%s: secret ID is required", i18n.T("ErrorValidation", nil))
	}
	if userID == 0 {
		return fmt.Errorf("%s: user ID is required", i18n.T("ErrorValidation", nil))
	}
	if len(perms) == 0 {
		return fmt.Errorf("%s: at least one permission is required", i18n.T("ErrorValidation", nil))
	}
	for _, p := range perms {
		if !slices.Contains(validACLPermissions, p) {
			return fmt.Errorf("%s: invalid ACL permission %q — must be one of %v", i18n.T("ErrorValidation", nil), p, validACLPermissions)
		}
	}

	// Verify the secret exists (this is defence-in-depth; the HTTP layer also resolves it).
	secret, err := c.requireSecret(ctx, secretID)
	if err != nil {
		return err
	}

	permsJSON, err := EncodeSecretACLPerms(perms)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	acl := &models.SecretACL{
		SecretID:    secretID,
		UserID:      userID,
		Permissions: permsJSON,
		GrantedBy:   actorID,
	}
	if err := c.storage.CreateOrUpdateSecretACL(ctx, acl); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	projectID := secret.ProjectID
	c.writeAuditEventFull(ctx, EventSecretACLGranted, actorPtr(actorID), &secretID, &projectID, "",
		fmt.Sprintf("granted user %d ACL %v on secret %d", userID, perms, secretID))
	return nil
}

// RevokeSecretACL removes the ACL row with the given aclID, verifying it belongs
// to secretID. actorID is the admin performing the revocation. Emits a
// secret.acl_revoked audit event.
func (c *KeyorixCore) RevokeSecretACL(ctx context.Context, actorID, secretID, aclID uint) error {
	if aclID == 0 {
		return fmt.Errorf("%s: ACL ID is required", i18n.T("ErrorValidation", nil))
	}

	// Look up all ACLs for this secret to verify the aclID belongs here.
	acls, err := c.storage.ListSecretACLs(ctx, secretID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	var found *models.SecretACL
	for _, a := range acls {
		if a.ID == aclID {
			found = a
			break
		}
	}
	if found == nil {
		return fmt.Errorf("%s: ACL %d does not belong to secret %d", i18n.T("ErrorNotFound", nil), aclID, secretID)
	}

	if err := c.storage.DeleteSecretACL(ctx, aclID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.writeAuditEvent(ctx, EventSecretACLRevoked, actorPtr(actorID), &secretID,
		fmt.Sprintf("revoked ACL %d (user %d) on secret %d", aclID, found.UserID, secretID))
	return nil
}

// ListSecretACLs returns all ACL grants for the given secret.
func (c *KeyorixCore) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	return c.storage.ListSecretACLs(ctx, secretID)
}

// HasSecretACL reports whether userID holds an explicit SecretACL grant on secretID
// that covers perm. Returns (false, nil) when no grant exists or the grant doesn't
// cover perm; only returns an error on storage failure.
func (c *KeyorixCore) HasSecretACL(ctx context.Context, userID, secretID uint, perm string) (bool, error) {
	acl, err := c.storage.GetSecretACL(ctx, secretID, userID)
	if err != nil {
		// "not found" is not an error; any other error is.
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	perms := DecodeSecretACLPerms(acl.Permissions)
	return slices.Contains(perms, perm), nil
}

// isNotFound reports whether err looks like a "not found" storage error.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "record not found")
}
