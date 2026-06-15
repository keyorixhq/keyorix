// migrate_user_to_machine.go — operator helper to convert a service-account-shaped
// human user into a project machine identity (ADR-023).
//
// Early deployments often model CI runners, automation, and service accounts as
// ordinary user records. ADR-023 keeps machine identities separate from humans so
// the Members view can segment the two and a future machine-token auth path can
// target them. This helper performs the one-way conversion: it materialises a
// machine identity for the user and (by default) suspends the source account so
// the human-login path is closed. The user is never deleted — suspension is
// reversible and preserves audit/ownership history that may still reference it.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MigrateUserToMachine converts the user identified by username into an active
// machine identity in projectID. identityType defaults to "service" and name
// defaults to the user's username. When suspendSource is true the source user is
// suspended (login blocked) so it can no longer authenticate as a human. actorID
// is the acting admin, recorded on every audit event. The created machine
// identity is returned.
func (c *KeyorixCore) MigrateUserToMachine(ctx context.Context, username string, projectID uint, identityType, name string, actorID uint, suspendSource bool) (*models.MachineIdentity, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}

	user, err := c.storage.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user %q not found: %w", username, err)
	}

	if identityType == "" {
		identityType = MachineTypeService
	}
	if name == "" {
		name = user.Username
	}
	desc := fmt.Sprintf("Migrated from user %q (id %d, %s)", user.Username, user.ID, user.Email)

	m, err := c.CreateMachineIdentity(ctx, projectID, name, identityType, desc, "", actorID)
	if err != nil {
		return nil, err
	}

	if suspendSource {
		if err := c.SuspendUser(ctx, actorID, user.ID); err != nil {
			// The identity exists; report the partial state so the operator can
			// suspend the source user manually rather than silently leaving an
			// active human login alongside the new machine identity.
			return m, fmt.Errorf("machine identity %d created but failed to suspend source user %d: %w", m.ID, user.ID, err)
		}
	}

	aid, pid := actorID, projectID
	c.writeAuditEventFull(ctx, "machine_identity.migrated_from_user", &aid, nil, &pid, "",
		fmt.Sprintf("user %q (id %d) migrated to machine identity %q (id %d) in project %d", user.Username, user.ID, m.Name, m.ID, projectID))

	return m, nil
}
