// bulk_delete.go — bulk deletion of secrets in a single call. Each deletion
// calls the same logic as single-secret delete (audit log, dependency events,
// ACL cleanup, etc.) rather than bypassing with a raw DB delete. Partial
// success is allowed — individual failures are collected in Failed.
// Project-scoped (route-gated secrets.delete). Parallels bulk-rename / extend-expiring.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// BulkDeleteRequest carries the set of secret node IDs to delete.
type BulkDeleteRequest struct {
	SecretIDs []uint `json:"secret_ids"`
}

// maxBulkDeleteBatchSize bounds how many secret IDs a single bulk-delete call
// accepts — each ID does a per-item storage round trip (GetSecret + DeleteSecret),
// so an unbounded list is a per-request resource-exhaustion vector (#G44), the
// same class of bug as maxBulkAccessRequestBatchSize (bulk_access_requests.go).
const maxBulkDeleteBatchSize = 500

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
// Each secret is fetched and deleted via the SAME authorization-checked path the
// singular delete endpoint uses (GetSecretWithPermissionCheck /
// DeleteSecretWithPermissionCheck) — not a raw, unauthorized GetSecret/DeleteSecret
// loop over caller-supplied IDs — so audit logging, dependency-invalidation events,
// and per-secret authorization (ACL/ownership, not just the coarse project check
// below) are all applied consistently with the single-secret path (#G31).
//
// projectID gates a mandatory cross-project guard: a secret belonging to a
// different project is rejected even if the caller holds a token with broad
// permissions. Unlike the prior version, projectID == 0 is refused outright rather
// than silently disabling the guard — a bulk delete must always be scoped to a
// real project. A secret outside the caller's project or authorization is reported
// identically to a nonexistent one ("secret not found"), never disclosing its name —
// the caller has no right to learn that ANOTHER tenant's secret exists at all.
// deletedBy is the authenticated username used in the audit trail.
func (c *KeyorixCore) BulkDeleteSecrets(ctx context.Context, req BulkDeleteRequest, projectID uint, deletedBy string, actorID uint, ip, ua string) (*BulkDeleteResult, error) {
	if len(req.SecretIDs) == 0 {
		return nil, fmt.Errorf("at least one secret ID is required")
	}
	if len(req.SecretIDs) > maxBulkDeleteBatchSize {
		return nil, fmt.Errorf("secret_ids exceeds the maximum batch size of %d", maxBulkDeleteBatchSize)
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project ID is required")
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

		// Per-secret authorization + fetch — the same check the singular delete
		// endpoint runs (secrets_crud.go's DeleteSecret handler). A secret the
		// caller cannot read (wrong project, no ACL/ownership grant, or genuinely
		// absent) is reported identically as "secret not found": its name must
		// never leak to a caller who was never authorized to see it.
		//
		// actorID == 0 is the embedded/local-CLI caller (bulk_delete.go's
		// runBulkDeleteEmbedded) — single-user local mode has no RBAC concept at
		// all, matching the singular CLI `secret delete` command's use of the
		// bare, unguarded GetSecret/DeleteSecret (delete.go): physical access to
		// the local DB file is the authorization boundary there, not a userID.
		// Every authenticated HTTP/gRPC caller always supplies a real actorID
		// (secrets_bulk_delete.go's handler uses userCtx.UserID), so this
		// fallback never weakens the multi-tenant per-ID re-authorization #G31
		// added for that path.
		var secret *models.SecretNode
		var err error
		if actorID == 0 {
			secret, err = c.GetSecret(ctx, id)
		} else {
			secret, err = c.GetSecretWithPermissionCheck(ctx, id, actorID)
		}
		if err != nil || secret == nil || secret.ProjectID != projectID {
			result.Failed = append(result.Failed, BulkOpError{
				SecretID: id,
				Error:    "secret not found",
			})
			continue
		}

		secretName := secret.Name
		secretProjectID := secret.ProjectID

		if actorID == 0 {
			err = c.DeleteSecret(ctx, id)
		} else {
			err = c.DeleteSecretWithPermissionCheck(ctx, id, actorID)
		}
		if err != nil {
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
