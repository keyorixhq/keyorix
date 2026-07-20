// rotation_dryrun.go — dry-run (simulation) for credential rotation (ADR-047).
//
// SimulateRotation validates a secret's rotation configuration without executing
// any actual rotation. It checks:
//   - policy_exists  : at least one active rotation policy covers the secret
//   - backend_known  : the secret's RotationBackend names a configured executor
//   - ref_non_empty  : the secret's RotationRef is non-empty
//   - ref_valid      : the RotationRef passes the same metacharacter validation
//     that SetSecretAutoRotate enforces at configuration time
//
// All checks are run and recorded even when an earlier one fails (except
// policy_exists: if the secret has no backend set AND no covering policy the
// remaining checks are still evaluated so the caller sees the full picture).
// Valid is true only when every check passed.
package core

import (
	"context"
	"fmt"
	"time"
)

// RotationDryRunRequest identifies which secret to simulate rotation for.
type RotationDryRunRequest struct {
	SecretID uint // ID of the secret whose rotation configuration to validate
}

// RotationDryRunResult is the outcome of a SimulateRotation call.
type RotationDryRunResult struct {
	SecretID    uint          `json:"secret_id"`
	SecretName  string        `json:"secret_name"`
	Backend     string        `json:"backend"`      // SecretNode.RotationBackend (may be empty)
	Ref         string        `json:"ref"`          // SecretNode.RotationRef (may be empty)
	Valid       bool          `json:"valid"`        // true only when all checks passed
	Checks      []DryRunCheck `json:"checks"`
	SimulatedAt time.Time     `json:"simulated_at"`
}

// DryRunCheck is the result of one named validation step.
type DryRunCheck struct {
	Name    string `json:"name"`             // policy_exists | backend_known | ref_non_empty | ref_valid
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"` // human-readable detail (always set on failure)
}

// SimulateRotation validates a secret's rotation configuration without executing
// the rotation. It returns an error only when the secret itself cannot be found;
// all other validation outcomes are encoded in the returned RotationDryRunResult.
func (c *KeyorixCore) SimulateRotation(ctx context.Context, req RotationDryRunRequest) (*RotationDryRunResult, error) {
	secret, err := c.storage.GetSecret(ctx, req.SecretID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	res := &RotationDryRunResult{
		SecretID:    secret.ID,
		SecretName:  secret.Name,
		Backend:     secret.RotationBackend,
		Ref:         secret.RotationRef,
		SimulatedAt: c.now(),
	}

	// Check 1 — policy_exists: at least one active rotation policy covers this secret.
	policyCheck := c.checkPolicyExists(ctx, secret.ProjectID, secret.EnvironmentID)
	res.Checks = append(res.Checks, policyCheck)

	// Check 2 — backend_known: the configured backend is registered in the rotation manager.
	backendCheck := c.checkBackendKnown(secret.RotationBackend)
	res.Checks = append(res.Checks, backendCheck)

	// Check 3 — ref_non_empty: the rotation ref is set.
	refEmptyCheck := checkRefNonEmpty(secret.RotationRef)
	res.Checks = append(res.Checks, refEmptyCheck)

	// Check 4 — ref_valid: the rotation ref passes the same metacharacter validation
	// enforced at configuration time (validateRotationRef).
	refValidCheck := checkRefValid(secret.RotationRef)
	res.Checks = append(res.Checks, refValidCheck)

	// Overall: all checks must pass.
	all := true
	for _, ch := range res.Checks {
		if !ch.Passed {
			all = false
			break
		}
	}
	res.Valid = all
	return res, nil
}

// checkPolicyExists reports whether at least one active rotation policy covers
// the given project/environment. It returns a passing check when any active
// policy is found, failing (with a message) otherwise.
//
// The function issues two queries because ListRotationPolicies' filters are
// additive (AND), so a single call cannot match both project-scoped policies
// (project_id=P, env_id=nil) and environment-scoped ones (project_id=nil,
// env_id=E). Both results are collected first, then evaluated together.
func (c *KeyorixCore) checkPolicyExists(ctx context.Context, projectID, environmentID uint) DryRunCheck {
	const name = "policy_exists"

	// Query 1: project-scoped policies for this project.
	projectPolicies, err := c.storage.ListRotationPolicies(ctx, &projectID, nil)
	if err != nil {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("could not list rotation policies: %v", err),
		}
	}

	// Query 2: environment-scoped policies for this environment.
	envPolicies, err := c.storage.ListRotationPolicies(ctx, nil, &environmentID)
	if err != nil {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("could not list rotation policies: %v", err),
		}
	}

	// Evaluate: first check project-scoped, then environment-scoped.
	for _, p := range projectPolicies {
		if p.IsActive && p.Scope == "project" {
			return DryRunCheck{Name: name, Passed: true, Message: fmt.Sprintf("covered by policy %q (id %d)", p.Name, p.ID)}
		}
	}
	for _, p := range envPolicies {
		if p.IsActive && p.Scope == "environment" {
			return DryRunCheck{Name: name, Passed: true, Message: fmt.Sprintf("covered by policy %q (id %d)", p.Name, p.ID)}
		}
	}

	return DryRunCheck{
		Name:    name,
		Passed:  false,
		Message: "no active rotation policy covers this secret",
	}
}

// checkBackendKnown reports whether the given backend name is registered in the
// rotation manager. An empty backend name is treated as "no backend configured"
// (not an error — some secrets rotate without a backend).
func (c *KeyorixCore) checkBackendKnown(backend string) DryRunCheck {
	const name = "backend_known"
	if backend == "" {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: "no rotation backend configured (RotationBackend is empty)",
		}
	}
	if c.rotationManager == nil {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("backend %q is not registered: no rotation backends are configured", backend),
		}
	}
	if _, ok := c.rotationManager.Get(backend); !ok {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("backend %q is not registered in the rotation manager", backend),
		}
	}
	return DryRunCheck{
		Name:    name,
		Passed:  true,
		Message: fmt.Sprintf("backend %q is registered", backend),
	}
}

// checkRefNonEmpty reports whether the rotation ref is non-empty.
func checkRefNonEmpty(ref string) DryRunCheck {
	const name = "ref_non_empty"
	if ref == "" {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: "rotation ref is empty (RotationRef must be set for backend rotation)",
		}
	}
	return DryRunCheck{Name: name, Passed: true, Message: fmt.Sprintf("ref %q is non-empty", ref)}
}

// checkRefValid reports whether the rotation ref passes the same metacharacter
// validation that SetSecretAutoRotate enforces at configuration time.
func checkRefValid(ref string) DryRunCheck {
	const name = "ref_valid"
	if ref == "" {
		// An empty ref is already caught by checkRefNonEmpty; treat it as valid here
		// so this check doesn't duplicate that failure with a misleading message.
		return DryRunCheck{Name: name, Passed: true, Message: "ref is empty (see ref_non_empty check)"}
	}
	if err := validateRotationRef(ref); err != nil {
		return DryRunCheck{
			Name:    name,
			Passed:  false,
			Message: err.Error(),
		}
	}
	return DryRunCheck{Name: name, Passed: true, Message: fmt.Sprintf("ref %q passed metacharacter validation", ref)}
}
