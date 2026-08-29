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
	"errors"
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

// ErrMachineTokenRevoked/ErrMachineTokenExpired are returned by
// ValidateMachineToken/CurrentMachineTokenRestriction on the same two
// conditions ErrPATRevoked/ErrPATExpired cover for PATs — the caller (auth
// middleware) surfaces either as a 401.
var (
	ErrMachineTokenRevoked = errors.New("token revoked")
	ErrMachineTokenExpired = errors.New("token expired")
)

// IssueMachineTokenResult carries the freshly minted token. PlainToken is shown
// once and never persisted (only its hash is stored).
type IssueMachineTokenResult struct {
	Credential        *models.MachineIdentityCredential
	PlainToken        string
	ReplacedTokenHash string // non-empty when ReplaceCredentialID was set; caller should evict auth cache
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
	// ReplaceCredentialID, when non-zero, atomically revokes the specified existing
	// credential immediately after the new one is issued (PAT-006: eliminates the
	// overlap window in the manual two-step issue-then-revoke rotation flow).
	// The credential must belong to the same machine; it is rejected if not found.
	ReplaceCredentialID uint
}

// validateReplacementCredential pre-validates the credential-to-replace (PAT-006):
// fetches it and confirms it belongs to the given machine. Returns the old token
// hash (for cache eviction) or empty string when replaceID is 0.
func (c *KeyorixCore) validateReplacementCredential(ctx context.Context, machineID, replaceID uint) (string, error) {
	if replaceID == 0 {
		return "", nil
	}
	oldCred, err := c.storage.GetMachineIdentityCredentialByID(ctx, replaceID)
	if err != nil || oldCred.MachineIdentityID != machineID {
		return "", fmt.Errorf("replace_credential_id: credential not found on this machine")
	}
	return oldCred.TokenHash, nil
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
	// MACH-001: enforce a privilege ceiling — a non-admin cannot issue a token for
	// a machine that holds admin-tier roles, since the token would carry those roles
	// and the actor could use it to escalate their own effective privileges. Every
	// caller of IssueMachineToken (CLI, gRPC, HTTP) passes a real user's ID, never a
	// machine principal's, so ActorTypeUser is exact here, not a default.
	if err := c.requireMachinePrivilegeCeiling(ctx, ActorTypeUser, actorID, projectID, machineID); err != nil {
		return nil, err
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

	// PAT-006: pre-validate the credential to replace BEFORE creating the new one
	// so we fail fast without leaving an orphaned new credential if the old ID is bad.
	oldCredHash, err := c.validateReplacementCredential(ctx, machineID, params.ReplaceCredentialID)
	if err != nil {
		return nil, err
	}

	var cidrJSON string
	if len(params.AllowedCIDRs) > 0 {
		validated, err := encodePATCIDRs(params.AllowedCIDRs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", "invalid CIDR allowlist", err)
		}
		cidrJSON = validated
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

	// PAT-006: revoke the replaced credential after the new one is safely stored so
	// the machine is never left without a valid credential during the rotation.
	if params.ReplaceCredentialID != 0 {
		if err := c.storage.RevokeMachineIdentityCredential(ctx, projectID, params.ReplaceCredentialID); err != nil {
			return nil, fmt.Errorf("new token issued but failed to revoke old credential %d: %w", params.ReplaceCredentialID, err)
		}
		c.logMachineEvent(ctx, "machine_identity.token_rotated", m, actorID)
		return &IssueMachineTokenResult{Credential: created, PlainToken: raw, ReplacedTokenHash: oldCredHash}, nil
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
	if err := c.storage.RevokeMachineIdentityCredential(ctx, projectID, credentialID); err != nil {
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
// role names, network restriction, and the credential's row id. It rejects
// revoked/expired credentials and any machine not in the active state. The
// middleware gates on the machineTokenPrefix before calling this.
//
// #G60: this deliberately does NOT touch last_used_at itself (sibling of the
// same fix in ValidatePATToken). The credential's network allowlist is
// evaluated by the CALLER (server/middleware, server/grpc/interceptors),
// strictly after this function returns — stamping last_used_at in here would
// record the credential as "used" even for a request the caller is about to
// reject outright for arriving from a disallowed network. The returned
// credential id lets the caller invoke TouchMachineTokenLastUsed itself, once
// its own restriction check has actually passed.
func (c *KeyorixCore) ValidateMachineToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, *MachineTokenRestriction, uint, error) {
	if !strings.HasPrefix(raw, machineTokenPrefix) {
		return nil, nil, nil, 0, fmt.Errorf("not a machine token")
	}
	cred, err := c.storage.GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("invalid token")
	}
	if cred.Revoked {
		return nil, nil, nil, 0, ErrMachineTokenRevoked
	}
	if cred.ExpiresAt != nil && c.now().After(*cred.ExpiresAt) {
		return nil, nil, nil, 0, ErrMachineTokenExpired
	}
	m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("machine identity not found")
	}
	if m.State != MachineActive {
		return nil, nil, nil, 0, fmt.Errorf("machine identity is %s", m.State)
	}

	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		return m, []string{}, machineRestrictionFrom(cred), cred.ID, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, machineRestrictionFrom(cred), cred.ID, nil
}

// TouchMachineTokenLastUsed records that machine credential credID was just
// used, subject to the same machineTouchInterval throttle the inline stamp
// always used. Split out of ValidateMachineToken (#G60) so the caller only
// stamps last_used_at AFTER its own network-restriction (CIDR allowlist)
// check has passed. Best-effort: never fails the caller's request.
func (c *KeyorixCore) TouchMachineTokenLastUsed(ctx context.Context, credID uint) {
	if credID == 0 {
		return
	}
	_ = c.storage.TouchMachineIdentityCredential(ctx, credID, c.now(), machineTouchInterval)
}

// CurrentMachineTokenRestriction re-fetches a machine token's network restriction
// fresh from storage by its raw token, mirroring CurrentPATRestriction (#146) —
// generalized to machine tokens as part of #G18. Before this, the auth
// middleware's cache-hit path only ever refreshed a PAT's restriction, so a
// machine token's AllowedCIDRs allowlist (and the credential's
// revoked/expired/machine-inactive state) kept being served from the stale
// cached UserContext snapshot for up to validTokenTTL. Returns
// ErrMachineTokenRevoked/ErrMachineTokenExpired, or a plain error when the
// machine identity itself is no longer active (mirroring ValidateMachineToken's
// own checks) — the caller must treat all three as "deny the request", not a
// transient lookup failure to degrade past.
func (c *KeyorixCore) CurrentMachineTokenRestriction(ctx context.Context, raw string) (*MachineTokenRestriction, error) {
	cred, err := c.storage.GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))
	if err != nil {
		return nil, err
	}
	if cred.Revoked {
		return nil, ErrMachineTokenRevoked
	}
	if cred.ExpiresAt != nil && c.now().After(*cred.ExpiresAt) {
		return nil, ErrMachineTokenExpired
	}
	m, err := c.storage.GetMachineIdentity(ctx, cred.MachineIdentityID)
	if err != nil {
		return nil, err
	}
	if m.State != MachineActive {
		return nil, fmt.Errorf("machine identity is %s", m.State)
	}
	return machineRestrictionFrom(cred), nil
}

// machineTokenCIDRCorrupted is returned by machineRestrictionFrom when the stored
// column is non-empty but fails JSON parsing. Returning nil would silently widen
// the token to global network access; the sentinel contains no valid CIDR so
// IPInCIDRs blocks all source IPs until the token is re-issued.
var machineTokenCIDRCorrupted = []string{"<corrupted>"}

// machineRestrictionFrom decodes the JSON AllowedCIDRs on a credential into a
// MachineTokenRestriction. Returns nil when no CIDRs are set.
func machineRestrictionFrom(cred *models.MachineIdentityCredential) *MachineTokenRestriction {
	if cred.AllowedCIDRs == "" {
		return nil
	}
	var cidrs []string
	if err := json.Unmarshal([]byte(cred.AllowedCIDRs), &cidrs); err != nil {
		return &MachineTokenRestriction{AllowedCIDRs: machineTokenCIDRCorrupted}
	}
	if len(cidrs) == 0 {
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
