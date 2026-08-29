// bulk_access_requests.go — bulk approve/reject for access requests plus CRUD
// for rejection-reason templates (ADR-024 extension).
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// maxBulkAccessRequestBatchSize bounds how many request IDs a single bulk
// approve/reject call may process. Enforced here in core (not just at the
// HTTP layer) so the CLI's embedded/local mode, which calls these functions
// directly, is covered too. The global request body-size limit alone still
// permits well over a million small integers in one JSON array, and the
// per-item loop below does one DB round trip per ID with no cancellation
// check — an unbounded batch is a per-request resource-exhaustion vector.
// 500 comfortably covers any legitimate UI-driven bulk action while bounding
// worst-case handler runtime and DB load.
const maxBulkAccessRequestBatchSize = 500

// ── Result types ─────────────────────────────────────────────────────────────

// BulkApproveResult is the outcome of a bulk-approve call.
type BulkApproveResult struct {
	Approved []uint            `json:"approved"`         // request IDs successfully approved
	Failed   []BulkAccessError `json:"failed,omitempty"` // per-item errors
}

// BulkRejectResult is the outcome of a bulk-reject call.
type BulkRejectResult struct {
	Rejected []uint            `json:"rejected"`         // request IDs successfully rejected
	Failed   []BulkAccessError `json:"failed,omitempty"` // per-item errors
}

// BulkAccessError pairs a request ID with the reason it could not be processed.
type BulkAccessError struct {
	RequestID uint   `json:"request_id"`
	Error     string `json:"error"`
}

// ── Bulk approve ──────────────────────────────────────────────────────────────

// BulkApproveAccessRequests approves multiple pending access requests on behalf
// of approverID. Each request is attempted independently: per-item failures are
// collected in the result rather than aborting the whole batch.
//
// The function delegates to the existing ApproveAccessRequest per item so all
// invariants (state check, self-approval guard, dual-control, role validation,
// project liveness, privilege ceiling) are enforced exactly once.
func (k *KeyorixCore) BulkApproveAccessRequests(ctx context.Context, requestIDs []uint, approverID uint) (*BulkApproveResult, error) {
	if len(requestIDs) == 0 {
		return nil, errors.New("request_ids is required")
	}
	if len(requestIDs) > maxBulkAccessRequestBatchSize {
		return nil, fmt.Errorf("request_ids exceeds the maximum batch size of %d", maxBulkAccessRequestBatchSize)
	}

	// Pre-fetch all requests in one query so we can resolve projectID per item
	// without N individual GetAccessRequest round trips.
	fetched, err := k.storage.ListAccessRequestsByIDs(ctx, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access requests: %w", err)
	}

	byID := make(map[uint]*models.AccessRequest, len(fetched))
	for _, r := range fetched {
		byID[r.ID] = r
	}

	result := &BulkApproveResult{}
	for _, id := range requestIDs {
		req, ok := byID[id]
		if !ok {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "access request not found",
			})
			continue
		}
		// Enforce project-scope roles.assign for each request individually. The HTTP
		// route uses the global RequirePermission gate (any global roles.assign holder
		// can reach this endpoint), but a global grant must not authorise action on
		// projects the caller has no per-project roles.assign at — that would be
		// cross-project approval. Mirror the RequireScopedPermission gate that the
		// single-request path (PUT /projects/{id}/access-requests/{requestId}) uses.
		if allowed, authErr := k.Authorize(ctx, approverID, permRolesAssign, Scope{ProjectID: req.ProjectID}); authErr != nil || !allowed {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "permission denied",
			})
			continue
		}
		// Delegate to existing single-request logic (carries all validation).
		// grantedRole="" → falls back to the request's SuggestedRole.
		_, approveErr := k.ApproveAccessRequest(ctx, req.ProjectID, id, approverID, "")
		if approveErr != nil {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     approveErr.Error(),
			})
			continue
		}
		result.Approved = append(result.Approved, id)
	}
	return result, nil
}

// ── Bulk reject ───────────────────────────────────────────────────────────────

// BulkRejectAccessRequests rejects multiple pending access requests with a
// shared reason on behalf of approverID. Each request is attempted independently;
// per-item failures are collected rather than aborting the whole batch.
//
// The function delegates to the existing RejectAccessRequest per item so all
// invariants (state check, etc.) are enforced exactly once.
func (k *KeyorixCore) BulkRejectAccessRequests(ctx context.Context, requestIDs []uint, approverID uint, reason string) (*BulkRejectResult, error) {
	if len(requestIDs) == 0 {
		return nil, errors.New("request_ids is required")
	}
	if len(requestIDs) > maxBulkAccessRequestBatchSize {
		return nil, fmt.Errorf("request_ids exceeds the maximum batch size of %d", maxBulkAccessRequestBatchSize)
	}
	if reason == "" {
		return nil, errors.New("reason is required")
	}

	fetched, err := k.storage.ListAccessRequestsByIDs(ctx, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access requests: %w", err)
	}

	byID := make(map[uint]*models.AccessRequest, len(fetched))
	for _, r := range fetched {
		byID[r.ID] = r
	}

	result := &BulkRejectResult{}
	for _, id := range requestIDs {
		req, ok := byID[id]
		if !ok {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "access request not found",
			})
			continue
		}
		if allowed, authErr := k.Authorize(ctx, approverID, permRolesAssign, Scope{ProjectID: req.ProjectID}); authErr != nil || !allowed {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "permission denied",
			})
			continue
		}
		_, rejectErr := k.RejectAccessRequest(ctx, req.ProjectID, id, approverID, 0, reason)
		if rejectErr != nil {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     rejectErr.Error(),
			})
			continue
		}
		result.Rejected = append(result.Rejected, id)
	}
	return result, nil
}

// ── Rejection reason templates ────────────────────────────────────────────────

// CreateRejectionReasonTemplate creates a new named rejection reason template.
func (k *KeyorixCore) CreateRejectionReasonTemplate(ctx context.Context, createdBy uint, name, reason string) (*models.RejectionReasonTemplate, error) {
	if name == "" {
		return nil, errors.New("name is required")
	}
	if reason == "" {
		return nil, errors.New("reason is required")
	}
	now := k.now()
	t := &models.RejectionReasonTemplate{
		Name:      name,
		Reason:    reason,
		CreatedBy: createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := k.storage.CreateRejectionReasonTemplate(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// ListRejectionReasonTemplates returns all rejection reason templates.
func (k *KeyorixCore) ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error) {
	return k.storage.ListRejectionReasonTemplates(ctx)
}

// EventRejectionReasonTemplateDeleted is emitted when a rejection-reason
// template is deleted, so the deletion is attributable to an actor in the
// audit trail. DeleteRejectionReasonTemplate previously took no actor at all
// (#G72) — callers (CLI `request rejection-templates delete`, the HTTP
// DELETE /rejection-reason-templates/{id} route) must resolve/authenticate
// the acting user before calling.
const EventRejectionReasonTemplateDeleted = "rejection_reason_template.deleted"

// DeleteRejectionReasonTemplate deletes the rejection reason template with the
// given ID on behalf of actorID, recording an audit event so the deletion is
// attributable (#G72).
func (k *KeyorixCore) DeleteRejectionReasonTemplate(ctx context.Context, actorID, id uint) error {
	if err := k.storage.DeleteRejectionReasonTemplate(ctx, id); err != nil {
		return err
	}
	k.writeAuditEvent(ctx, EventRejectionReasonTemplateDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("rejection-reason template %d deleted", id))
	return nil
}
