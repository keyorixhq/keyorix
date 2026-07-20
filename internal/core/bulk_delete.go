// bulk_delete.go — bulk deletion of secrets in a single call. Each deletion
// calls the same logic as single-secret delete (audit log, dependency events,
// ACL cleanup, etc.) rather than bypassing with a raw DB delete. Partial
// success is allowed — individual failures are collected in Failed.
// Project-scoped (route-gated secrets.delete). Parallels bulk-rename / extend-expiring.
package core

import (
	"context"
	"fmt"
)

// BulkDeleteRequest carries the set of secret node IDs to delete.
type BulkDeleteRequest struct {
	SecretIDs []uint `json:"secret_ids"`
}

// BulkOpError captures why a single secret in a bulk operation could not be processed.
type BulkOpError struct {
	SecretID uint   `json:"secret_id"`
	Name     string `json:"name,omitempty"`
	Error    string `json:"error"`
}

// BulkDeleteResult reports outcome counts and per-secret failures.
type BulkDeleteResult struct {
	Deleted []uint        `json:"deleted"`
	Failed  []BulkOpError `json:"failed"`
	Total   int           `json:"total"`
}

// BulkDeleteSecrets deletes multiple secrets by ID within a project.
// Partial success is allowed — individual failures are collected in Failed.
// Each deletion calls DeleteSecret (the same path as single-secret delete)
// so audit logging, dependency-invalidation events, and any other cleanup
// are all applied consistently.
//
// projectID gates a cross-project guard: a secret belonging to a different
// project is rejected even if the caller holds a token with broad permissions.
// deletedBy is the authenticated username used in the audit trail.
func (c *KeyorixCore) BulkDeleteSecrets(ctx context.Context, req BulkDeleteRequest, projectID uint, deletedBy string, actorID uint, ip, ua string) (*BulkDeleteResult, error) {
	if len(req.SecretIDs) == 0 {
		return nil, fmt.Errorf("at least one secret ID is required")
	}

	result := &BulkDeleteResult{
		Deleted: make([]uint, 0, len(req.SecretIDs)),
		Failed:  make([]BulkOpError, 0),
		Total:   len(req.SecretIDs),
	}

	for _, id := range req.SecretIDs {
		if id == 0 {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: 0,
				Error:    "secret ID must be non-zero",
			})
			continue
		}

		// Pre-fetch the secret so we have its name and project for the audit
		// trail even after the row is soft-deleted, and for the cross-project guard.
		secret, err := c.storage.GetSecret(ctx, id)
		if err != nil || secret == nil {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: id,
				Error:    "secret not found",
			})
			continue
		}

		// Cross-project guard: bulk delete is project-scoped; a caller must not
		// reach secrets belonging to another project.
		if projectID != 0 && secret.ProjectID != projectID {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: id,
				Name:     secret.Name,
				Error:    "secret does not belong to this project",
			})
			continue
		}

		secretName := secret.Name
		secretProjectID := secret.ProjectID

		if err := c.DeleteSecret(ctx, id); err != nil {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: id,
				Name:     secretName,
				Error:    err.Error(),
			})
			continue
		}

		// Audit: same event shape as the single-delete handler's post-delete log.
		auditCtx := DetachedAuditContext(ctx)
		go func(sID, projID, aID uint, name, actor, remoteIP, userAgent string) {
			c.LogSecretDeletedWithProject(auditCtx, aID, sID, projID, actor, name, remoteIP, userAgent)
		}(id, secretProjectID, actorID, secretName, deletedBy, ip, ua)

		result.Deleted = append(result.Deleted, id)
	}

	return result, nil
}
