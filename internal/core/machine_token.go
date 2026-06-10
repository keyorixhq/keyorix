// machine_token.go — machine-identity authentication + RBAC (ADR-030).
//
// Machine identities (ADR-023) can now hold opaque bearer tokens and be granted
// project-scoped roles, so a CI/automation/Kubernetes workload can authenticate
// to the API as a least-privilege principal. Tokens mirror personal access
// tokens (hashed at rest, kx_machine_ prefix); role grants mirror user_roles.
package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	machineTokenPrefix = "kx_machine_"
	// machineTouchInterval throttles last_used_at writes on the auth hot path.
	machineTouchInterval = 30 * time.Second
)

// IssueMachineTokenResult carries the freshly minted token. PlainToken is shown
// once and never persisted (only its hash is stored).
type IssueMachineTokenResult struct {
	Credential *models.MachineIdentityCredential
	PlainToken string
}

// IssueMachineToken mints an opaque bearer token for an active machine identity.
// The raw token is returned once for out-of-band delivery; only its SHA-256 hash
// is stored. Issuing requires the machine to be active.
func (c *KeyorixCore) IssueMachineToken(ctx context.Context, machineID uint, name string, expiresAt *time.Time, actorID uint) (*IssueMachineTokenResult, error) {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil {
		return nil, fmt.Errorf("machine identity not found")
	}
	if m.State != MachineActive {
		return nil, fmt.Errorf("cannot issue a token for a %s machine identity (must be active)", m.State)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	raw := machineTokenPrefix + base64.RawURLEncoding.EncodeToString(b)

	cred := &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              strings.TrimSpace(name),
		TokenHash:         sha256Hex(raw),
		TokenPrefix:       raw[:len(machineTokenPrefix)+6], // "kx_machine_ab12cd"
		ExpiresAt:         expiresAt,
		CreatedAt:         c.now(),
	}
	created, err := c.storage.CreateMachineIdentityCredential(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to store machine token: %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity.token_issued", m, actorID)
	return &IssueMachineTokenResult{Credential: created, PlainToken: raw}, nil
}

// ListMachineTokens returns a machine's credentials (hashes are never exposed by the DTO).
func (c *KeyorixCore) ListMachineTokens(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	return c.storage.ListMachineIdentityCredentials(ctx, machineID)
}

// RevokeMachineToken revokes one credential after verifying it belongs to the machine.
func (c *KeyorixCore) RevokeMachineToken(ctx context.Context, machineID, credentialID, actorID uint) error {
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil || cred.MachineIdentityID != machineID {
		return fmt.Errorf("token not found")
	}
	if err := c.storage.RevokeMachineIdentityCredential(ctx, credentialID); err != nil {
		return err
	}
	if m, err := c.storage.GetMachineIdentity(ctx, machineID); err == nil {
		c.logMachineEvent(ctx, "machine_identity.token_revoked", m, actorID)
	}
	return nil
}

// ValidateMachineToken resolves a raw machine token to its identity and granted
// role names. It rejects revoked/expired credentials and any machine not in the
// active state, and best-effort throttled-updates last_used_at. The middleware
// gates on the machineTokenPrefix before calling this.
func (c *KeyorixCore) ValidateMachineToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, error) {
	if !strings.HasPrefix(raw, machineTokenPrefix) {
		return nil, nil, fmt.Errorf("not a machine token")
	}
	cred, err := c.storage.GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token")
	}
	if cred.Revoked {
		return nil, nil, fmt.Errorf("token revoked")
	}
	if cred.ExpiresAt != nil && c.now().After(*cred.ExpiresAt) {
		return nil, nil, fmt.Errorf("token expired")
	}
	m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID)
	if err != nil {
		return nil, nil, fmt.Errorf("machine identity not found")
	}
	if m.State != MachineActive {
		return nil, nil, fmt.Errorf("machine identity is %s", m.State)
	}

	// Best-effort, throttled last-used stamp — never fails the request.
	_ = c.storage.TouchMachineIdentityCredential(ctx, cred.ID, c.now(), machineTouchInterval)

	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		return m, []string{}, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, nil
}

// AssignMachineRole grants a role to a machine identity at the given scope and
// audits it. The caller (handler) gates on roles.assign at the project scope.
func (c *KeyorixCore) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint) error {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil {
		return fmt.Errorf("machine identity not found")
	}
	if err := c.storage.AssignMachineRole(ctx, machineID, roleID, scope); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.role_granted", m, actorID)
	return nil
}

// RemoveMachineRole revokes a machine identity's role grant at the given scope.
func (c *KeyorixCore) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint) error {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil {
		return fmt.Errorf("machine identity not found")
	}
	if err := c.storage.RemoveMachineRole(ctx, machineID, roleID, scope); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.role_removed", m, actorID)
	return nil
}

// ListMachineRoles returns every role granted to a machine identity (for display).
func (c *KeyorixCore) ListMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	return c.storage.GetMachineRoles(ctx, machineID)
}
