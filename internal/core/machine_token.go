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
	"encoding/json"
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

// machineInProject fetches a machine identity and verifies it belongs to the
// given project. Every project-scoped machine operation goes through here so a
// caller authorized at project A cannot act on a machine in project B by passing
// its id in the path (the route gate only proves rights at the path's project).
// A project mismatch is reported as "not found" to avoid cross-project id
// enumeration.
func (c *KeyorixCore) machineInProject(ctx context.Context, projectID, machineID uint) (*models.MachineIdentity, error) {
	m, err := c.storage.GetMachineIdentity(ctx, machineID)
	if err != nil || m.ProjectID != projectID {
		return nil, fmt.Errorf("machine identity not found")
	}
	return m, nil
}

// IssueMachineTokenParams groups the token-specific fields for IssueMachineToken.
type IssueMachineTokenParams struct {
	Name           string
	ExpiresAt      *time.Time
	Classification string
	AllowedCIDRs   []string
}

// IssueMachineToken mints an opaque bearer token for an active machine identity.
// The raw token is returned once for out-of-band delivery; only its SHA-256 hash
// is stored. params.AllowedCIDRs, when non-nil and non-empty, restricts the token
// to requests whose source IP falls within one of the listed CIDR blocks.
func (c *KeyorixCore) IssueMachineToken(ctx context.Context, projectID, machineID, actorID uint, params IssueMachineTokenParams) (*IssueMachineTokenResult, error) {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	if m.State != MachineActive {
		return nil, fmt.Errorf("cannot issue a token for a %s machine identity (must be active)", m.State)
	}
	classification := params.Classification
	if !IsValidClassification(classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	// Default a token's classification to its machine identity's tier when unset.
	if classification == "" {
		classification = m.Classification
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	raw := machineTokenPrefix + base64.RawURLEncoding.EncodeToString(b)

	var cidrJSON string
	if len(params.AllowedCIDRs) > 0 {
		b, _ := json.Marshal(params.AllowedCIDRs)
		cidrJSON = string(b)
	}
	cred := &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              strings.TrimSpace(params.Name),
		TokenHash:         sha256Hex(raw),
		TokenPrefix:       raw[:len(machineTokenPrefix)+6], // "kx_machine_ab12cd"
		AllowedCIDRs:      cidrJSON,
		ExpiresAt:         params.ExpiresAt,
		Classification:    classification,
		CreatedAt:         c.now(),
	}
	created, err := c.storage.CreateMachineIdentityCredential(ctx, cred)
	if err != nil {
		return nil, fmt.Errorf("failed to store machine token: %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity.token_issued", m, actorID)
	return &IssueMachineTokenResult{Credential: created, PlainToken: raw}, nil
}

// ListMachineTokens returns a machine's credentials (hashes are never exposed by
// the DTO), after verifying the machine belongs to the project.
func (c *KeyorixCore) ListMachineTokens(ctx context.Context, projectID, machineID uint) ([]*models.MachineIdentityCredential, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.ListMachineIdentityCredentials(ctx, machineID)
}

// RevokeMachineToken revokes one credential after verifying the machine belongs
// to the project and the credential belongs to the machine. It returns the revoked
// token's hash so the caller can evict it from the auth cache immediately (the HTTP
// token cache is keyed by SHA-256(raw) == TokenHash); without that a revoked machine
// token keeps authenticating until the positive-cache TTL.
func (c *KeyorixCore) RevokeMachineToken(ctx context.Context, projectID, machineID, credentialID, actorID uint) (tokenHash string, err error) {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return "", err
	}
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil || cred.MachineIdentityID != machineID {
		return "", fmt.Errorf("token not found")
	}
	if err := c.storage.RevokeMachineIdentityCredential(ctx, credentialID); err != nil {
		return "", err
	}
	c.logMachineEvent(ctx, "machine_identity.token_revoked", m, actorID)
	return cred.TokenHash, nil
}

// MachineTokenHashes returns the hashes of all of a machine identity's credentials,
// so the caller can evict them from the auth cache when the identity is suspended or
// revoked (which must reject its tokens immediately, not after the cache TTL).
func (c *KeyorixCore) MachineTokenHashes(ctx context.Context, machineID uint) ([]string, error) {
	creds, err := c.storage.ListMachineIdentityCredentials(ctx, machineID)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(creds))
	for _, cr := range creds {
		if cr.TokenHash != "" {
			hashes = append(hashes, cr.TokenHash)
		}
	}
	return hashes, nil
}

// ClassifyMachineToken sets (or clears, with "") the data-classification label on a
// machine credential, after verifying the machine belongs to the project and the
// credential to the machine. Audited.
func (c *KeyorixCore) ClassifyMachineToken(ctx context.Context, projectID, machineID, credentialID uint, level string, actorID uint) (*models.MachineIdentityCredential, error) {
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	cred, err := c.storage.GetMachineIdentityCredentialByID(ctx, credentialID)
	if err != nil || cred.MachineIdentityID != machineID {
		return nil, fmt.Errorf("token not found")
	}
	if cred.Classification == level {
		return cred, nil // no-op
	}
	old := cred.Classification
	cred.Classification = level
	if err := c.storage.UpdateMachineIdentityCredential(ctx, cred); err != nil {
		return nil, err
	}
	aid, pid := actorID, m.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "machine_identity.token_classified", &aid, nil, &pid, "",
		fmt.Sprintf("machine credential %d (machine %d) classification set to %q", cred.ID, machineID, level), diff)
	return cred, nil
}

// ValidateMachineToken resolves a raw machine token to its identity, granted
// role names, and network restriction. It rejects revoked/expired credentials
// and any machine not in the active state, and best-effort throttled-updates
// last_used_at. The middleware gates on the machineTokenPrefix before calling this.
func (c *KeyorixCore) ValidateMachineToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, *MachineTokenRestriction, error) {
	if !strings.HasPrefix(raw, machineTokenPrefix) {
		return nil, nil, nil, fmt.Errorf("not a machine token")
	}
	cred, err := c.storage.GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid token")
	}
	if cred.Revoked {
		return nil, nil, nil, fmt.Errorf("token revoked")
	}
	if cred.ExpiresAt != nil && c.now().After(*cred.ExpiresAt) {
		return nil, nil, nil, fmt.Errorf("token expired")
	}
	m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("machine identity not found")
	}
	if m.State != MachineActive {
		return nil, nil, nil, fmt.Errorf("machine identity is %s", m.State)
	}

	// Best-effort, throttled last-used stamp — never fails the request.
	_ = c.storage.TouchMachineIdentityCredential(ctx, cred.ID, c.now(), machineTouchInterval)

	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		return m, []string{}, machineRestrictionFrom(cred), nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, machineRestrictionFrom(cred), nil
}

// machineRestrictionFrom decodes the JSON AllowedCIDRs on a credential into a
// MachineTokenRestriction. Returns nil when no CIDRs are set.
func machineRestrictionFrom(cred *models.MachineIdentityCredential) *MachineTokenRestriction {
	if cred.AllowedCIDRs == "" {
		return nil
	}
	var cidrs []string
	if err := json.Unmarshal([]byte(cred.AllowedCIDRs), &cidrs); err != nil || len(cidrs) == 0 {
		return nil
	}
	return &MachineTokenRestriction{AllowedCIDRs: cidrs}
}

// AssignMachineRole grants a role to a machine identity at the given scope and
// audits it. The machine must belong to scope.ProjectID — the caller is only
// proven to hold roles.assign at that project, so a machine in another project
// must not be reachable through this path. Granting an admin role is additionally
// gated by requireAuthorityForRole (the same escalation-by-proxy ceiling
// AddProjectMember applies) — an admin-credentialed machine identity is just as
// much a self-escalation vector as an admin user grant. Also gated by the #419
// separation-of-duties preventive check (requireMachineGrantNoSoDViolation,
// sod.go) — a machine identity holds real permissions too and Authorize
// authorizes it, so the same toxic-permission-pair concern applies.
func (c *KeyorixCore) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint) error {
	m, err := c.machineInProject(ctx, scope.ProjectID, machineID)
	if err != nil {
		return err
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return err
	}
	if err := c.requireAuthorityForRole(ctx, actorID, scope.ProjectID, role.Name); err != nil {
		return err
	}
	if err := c.requireMachineGrantNoSoDViolation(ctx, machineID, roleID); err != nil {
		return err
	}
	if err := c.storage.AssignMachineRole(ctx, machineID, roleID, scope); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.role_granted", m, actorID)
	return nil
}

// RemoveMachineRole revokes a machine identity's role grant at the given scope.
func (c *KeyorixCore) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope Scope, actorID uint) error {
	m, err := c.machineInProject(ctx, scope.ProjectID, machineID)
	if err != nil {
		return err
	}
	if err := c.storage.RemoveMachineRole(ctx, machineID, roleID, scope); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.role_removed", m, actorID)
	return nil
}

// ListMachineRoles returns every role granted to a machine identity in the
// given project (for display), after verifying the machine belongs to it.
func (c *KeyorixCore) ListMachineRoles(ctx context.Context, projectID, machineID uint) ([]*models.Role, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.GetMachineRoles(ctx, machineID)
}
