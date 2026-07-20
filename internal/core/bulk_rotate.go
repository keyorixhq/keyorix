// bulk_rotate.go — BulkRotateSecrets: trigger rotation for multiple secrets in one call.
// Incident response: "rotate everything tagged confidential in project X" in a single
// operation instead of one call per secret. Secrets without auto-rotate configured are
// skipped (reported in Failed with reason "no rotation config") — they never silently
// block the rest. Returns partial results; never returns a top-level error unless the
// ENTIRE operation cannot begin (e.g. invalid arguments or DB connectivity failure on
// the initial load).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// BulkRotateRequest describes a bulk rotation request. SecretIDs is an explicit list;
// if empty the operation rotates every matching secret in ProjectID (with optional EnvID
// and Classification filters). ProjectID is required in all cases.
type BulkRotateRequest struct {
	// SecretIDs: explicit list of secret IDs to rotate. When non-empty, ProjectID is
	// still required as a cross-project guard — only secrets that actually belong to
	// ProjectID are rotated; others are reported as failures.
	SecretIDs []uint
	// ProjectID scopes the operation. Required.
	ProjectID uint
	// EnvID optionally restricts a project-wide rotation to one environment.
	// Ignored when SecretIDs is non-empty.
	EnvID uint
	// Classification optionally restricts a project-wide rotation to secrets with
	// a specific classification label (e.g. "confidential"). Empty = all.
	// Ignored when SecretIDs is non-empty.
	Classification string
	// RotatedBy is the actor string recorded on each rotation (username, "system:", etc.).
	RotatedBy string
}

// BulkRotateResult summarises the outcome. Triggered contains every secret ID for
// which rotation was successfully scheduled; Failed lists the rest with per-entry
// reasons. Never nil.
type BulkRotateResult struct {
	Triggered []uint           `json:"triggered"`
	Failed    []BulkRotateError `json:"failed,omitempty"`
	Total     int              `json:"total"`
}

// BulkRotateError is a per-secret failure entry in BulkRotateResult.
type BulkRotateError struct {
	SecretID uint   `json:"secret_id"`
	Name     string `json:"name,omitempty"`
	Error    string `json:"error"`
}

// BulkRotateSecrets schedules rotation for all matching secrets.
//
// When req.SecretIDs is non-empty, only those secrets are processed. Each is
// checked against req.ProjectID so a project-scoped caller cannot rotate another
// project's secrets by guessing IDs.
//
// When req.SecretIDs is empty, every live secret in req.ProjectID is processed,
// with optional req.EnvID and req.Classification filters.
//
// For each secret: if AutoRotate is not enabled, the secret is reported in
// BulkRotateResult.Failed with reason "no rotation config" — it is never treated
// as a fatal error. Otherwise, rotation is triggered via RotateSecretOnDemand.
//
// Returns partial results; individual secret failures do not abort the run.
// Returns an error only if the request is structurally invalid or the initial
// secret load fails entirely.
func (c *KeyorixCore) BulkRotateSecrets(ctx context.Context, req BulkRotateRequest) (*BulkRotateResult, error) {
	if req.ProjectID == 0 {
		return nil, fmt.Errorf("project ID is required")
	}
	if req.RotatedBy == "" {
		req.RotatedBy = "system:bulk-rotate"
	}

	result := &BulkRotateResult{
		Triggered: []uint{},
		Failed:    []BulkRotateError{},
	}

	if len(req.SecretIDs) > 0 {
		return result, c.bulkRotateExplicit(ctx, req, result)
	}

	// Project-wide: list all matching secrets. Use the storage ceiling page size (10 000)
	// so we get all secrets in one shot; Page=1 with a large PageSize is the established
	// pattern for trusted internal callers (see inventory/csv export callers in this repo).
	const bulkRotatePageSize = 10000
	filter := &storage.SecretFilter{
		ProjectID: &req.ProjectID,
		Page:      1,
		PageSize:  bulkRotatePageSize,
	}
	if req.EnvID != 0 {
		filter.EnvironmentID = &req.EnvID
	}
	if req.Classification != "" {
		filter.Classification = &req.Classification
	}
	isSecret := true
	filter.IsSecret = &isSecret

	secrets, _, err := c.storage.ListSecrets(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list secrets for project %d: %w", req.ProjectID, err)
	}

	for _, s := range secrets {
		result.Total++
		if !s.AutoRotate {
			result.Failed = append(result.Failed, BulkRotateError{
				SecretID: s.ID,
				Name:     s.Name,
				Error:    "no rotation config",
			})
			continue
		}
		_ = c.bulkRotateOne(ctx, s.ID, s.RotationLength, s.RotationCharset, req.RotatedBy, result)
	}
	return result, nil
}

// bulkRotateExplicit processes an explicit list of secret IDs, checking project membership
// and rotation eligibility before triggering each one.
func (c *KeyorixCore) bulkRotateExplicit(ctx context.Context, req BulkRotateRequest, result *BulkRotateResult) error {
	secrets, err := c.storage.GetSecretsByIDs(ctx, req.SecretIDs)
	if err != nil {
		return fmt.Errorf("load secrets: %w", err)
	}
	found := make(map[uint]bool, len(secrets))
	for _, s := range secrets {
		found[s.ID] = true
	}
	for _, id := range req.SecretIDs {
		if !found[id] {
			result.Failed = append(result.Failed, BulkRotateError{SecretID: id, Error: "secret not found"})
			result.Total++
		}
	}
	for _, s := range secrets {
		result.Total++
		if s.ProjectID != req.ProjectID {
			result.Failed = append(result.Failed, BulkRotateError{SecretID: s.ID, Name: s.Name, Error: "secret does not belong to this project"})
			continue
		}
		if !s.IsSecret {
			result.Failed = append(result.Failed, BulkRotateError{SecretID: s.ID, Name: s.Name, Error: "not a secret (folder nodes cannot be rotated)"})
			continue
		}
		if !s.AutoRotate {
			result.Failed = append(result.Failed, BulkRotateError{SecretID: s.ID, Name: s.Name, Error: "no rotation config"})
			continue
		}
		_ = c.bulkRotateOne(ctx, s.ID, s.RotationLength, s.RotationCharset, req.RotatedBy, result)
	}
	return nil
}

// bulkRotateOne generates a fresh value and rotates a single secret via RotateSecretOnDemand.
// On success it appends the secret ID to result.Triggered; on failure it appends to
// result.Failed. Returns a non-nil error only when value generation itself fails.
func (c *KeyorixCore) bulkRotateOne(ctx context.Context, secretID uint, rotationLength int, rotationCharset, rotatedBy string, result *BulkRotateResult) error {
	val, err := generateRotatedValueSpec(rotationLength, rotationCharset)
	if err != nil {
		result.Failed = append(result.Failed, BulkRotateError{
			SecretID: secretID,
			Error:    fmt.Sprintf("generate value: %v", err),
		})
		return err
	}
	if _, err := c.RotateSecretOnDemand(ctx, secretID, []byte(val), rotatedBy); err != nil {
		result.Failed = append(result.Failed, BulkRotateError{
			SecretID: secretID,
			Error:    err.Error(),
		})
		return nil // rotation error is per-secret, not fatal
	}
	result.Triggered = append(result.Triggered, secretID)
	return nil
}
