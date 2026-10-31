// oidc.go — machine-identity federation via OIDC / Kubernetes JWTs (ADR-031).
//
// An external workload (e.g. a Kubernetes pod with a projected service-account
// token) presents a JWT instead of a Keyorix-issued secret. The verifier checks
// the signature against the issuer's JWKS and validates iss/aud/exp; the core
// then maps the (issuer, subject) to a machine identity and resolves its roles —
// reusing the ADR-030 machine principal, RBAC, and audit path unchanged.
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SetOIDCVerifier wires the federation verifier (built from config at startup).
// nil disables OIDC auth.
func (c *KeyorixCore) SetOIDCVerifier(v *OIDCVerifier) {
	c.oidcVerifier = v
}

// OIDCEnabled reports whether federated authentication is configured.
func (c *KeyorixCore) OIDCEnabled() bool {
	return c.oidcVerifier != nil
}

// ValidateOIDCToken verifies a federated JWT and resolves it to its bound
// machine identity + roles (ADR-031), mirroring ValidateMachineToken so the
// middleware builds the same machine principal. Rejects when OIDC is disabled,
// the token fails verification, no binding exists, or the machine is not active.
// A storage failure while reading the machine's roles returns
// ErrRoleResolutionUnavailable (#2748) — never an empty role list.
//
// The third return value is the token's own exp (UTC): a caller that caches the
// result must not keep it past that instant (OIDC-EXPIRY-CAP-1).
func (c *KeyorixCore) ValidateOIDCToken(ctx context.Context, raw string) (*models.MachineIdentity, []string, time.Time, error) {
	if c.oidcVerifier == nil {
		return nil, nil, time.Time{}, fmt.Errorf("oidc authentication is not enabled")
	}
	issuer, subject, exp, err := c.oidcVerifier.VerifyWithExpiry(ctx, raw)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	m, err := c.storage.GetMachineByOIDCSubject(ctx, issuer, subject)
	if err != nil {
		return nil, nil, time.Time{}, credentialLookupError(err, "no machine identity bound to this token")
	}
	if m.State != MachineActive {
		// #2518: the same typed sentinel the opaque-token paths return for this
		// identical condition (machine_token.go). This path has no positive
		// auth cache today, so nothing can mistake it for a transient failure —
		// kept in step so a future cached OIDC path cannot inherit the trap.
		return nil, nil, time.Time{}, fmt.Errorf("%w: %s", ErrMachineIdentityNotActive, m.State)
	}
	roles, err := c.storage.GetMachineRoles(ctx, m.ID)
	if err != nil {
		// #2748: same fix as ValidateMachineToken's own GetMachineRoles branch
		// (and #1944's for the two user-credential validators) — a storage
		// failure resolving roles is retryable, not a successful validation
		// with no grants. See ErrRoleResolutionUnavailable.
		return nil, nil, time.Time{}, ErrRoleResolutionUnavailable
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return m, roleNames, exp, nil
}

// --- Binding management (ADR-031) ---

// CreateOIDCBinding binds an external (issuer, subject) to a machine identity in
// the given project. Audited; the machine must belong to the project (the
// handler also gates roles.assign there).
//
// (issuer, subject) is a GLOBAL namespace — GetMachineByOIDCSubject / the token
// verify path resolve it with no project scoping — but until this check, only
// project-scoped authority (roles.assign within THAT project) was required to
// claim a slice of it (#127). A project-A admin could pre-claim another team's
// well-known, not-yet-bound subject (predictable per issuer, e.g. a Kubernetes
// service-account or CI workflow identity) for their own machine; the victim
// workload's genuine token would then authenticate as the attacker's machine
// identity instead. Creating a binding is therefore gated on GLOBAL admin
// authority, matching the scope of what it actually claims.
func (c *KeyorixCore) CreateOIDCBinding(ctx context.Context, projectID, machineID uint, issuer, subject string, actorID uint) (*models.MachineIdentityOIDCBinding, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("issuer and subject are required")
	}
	if err := c.requireAdminAuthorityAt(ctx, actorID, 0); err != nil {
		return nil, fmt.Errorf("binding an OIDC subject requires install-wide admin authority: %w", err)
	}
	// Surface operator typos early: a binding to an issuer Keyorix doesn't trust
	// would never authenticate (Verify rejects untrusted issuers independently),
	// so reject it at creation when OIDC is configured.
	if c.oidcVerifier != nil && !c.oidcVerifier.TrustsIssuer(strings.TrimSpace(issuer)) {
		return nil, fmt.Errorf("issuer %q is not a configured trusted OIDC issuer", issuer)
	}
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return nil, err
	}
	b, err := c.storage.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: machineID,
		Issuer:            strings.TrimSpace(issuer),
		Subject:           strings.TrimSpace(subject),
		CreatedBy:         actorID,
		CreatedAt:         c.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC binding (already bound?): %w", err)
	}
	c.logMachineEvent(ctx, "machine_identity.oidc_bound", m, actorID)
	return b, nil
}

// ListOIDCBindings returns a machine's OIDC bindings (after the project check).
func (c *KeyorixCore) ListOIDCBindings(ctx context.Context, projectID, machineID uint) ([]*models.MachineIdentityOIDCBinding, error) {
	if _, err := c.machineInProject(ctx, projectID, machineID); err != nil {
		return nil, err
	}
	return c.storage.ListOIDCBindings(ctx, machineID)
}

// DeleteOIDCBinding removes a binding after verifying it belongs to the machine
// and the machine belongs to the project.
func (c *KeyorixCore) DeleteOIDCBinding(ctx context.Context, projectID, machineID, bindingID, actorID uint) error {
	m, err := c.machineInProject(ctx, projectID, machineID)
	if err != nil {
		return err
	}
	b, err := c.storage.GetOIDCBindingByID(ctx, bindingID)
	if err != nil {
		return classifyReadError(err, "binding not found")
	}
	if b.MachineIdentityID != machineID {
		return fmt.Errorf("binding not found")
	}
	if err := c.storage.DeleteOIDCBinding(ctx, bindingID); err != nil {
		return err
	}
	c.logMachineEvent(ctx, "machine_identity.oidc_unbound", m, actorID)
	return nil
}
