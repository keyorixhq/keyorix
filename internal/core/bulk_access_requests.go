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

// approverPrincipal derives the (actorType, principalID) pair for an
// (approverID, approverMachineID) approver tuple — the ONE place the bulk paths
// turn that tuple into something AuthorizePrincipal can resolve, so the two
// bulk functions cannot drift apart.
//
// #2495: a machine identity's approverID is always 0 (ADR-030 — a machine has no
// UserID), so "approverID==0" alone cannot tell a machine caller from the
// unauthenticated/system pseudo-actor. The machine ID is the only
// discriminator, which is why the bulk entry points require it from their
// caller instead of defaulting it.
func approverPrincipal(approverID, approverMachineID uint) (actorType string, principalID uint) {
	if approverMachineID != 0 {
		return ActorTypeMachine, approverMachineID
	}
	return ActorTypeUser, approverID
}

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
// of the (approverID, approverMachineID) principal. Each request is attempted
// independently: per-item failures are collected in the result rather than
// aborting the whole batch.
//
// The function delegates to the single-request path per item so all invariants
// (state check, self-approval guard, dual-control, role validation, project
// liveness, privilege ceiling) are enforced exactly once.
//
// approverMachineID is the acting MACHINE identity, or 0 for a human approver —
// the same convention ApproveAccessRequestWithExpiry takes (#1573). It is
// mandatory here rather than derived, because it cannot be derived: a machine
// caller's approverID is 0 (ADR-030: a machine identity has no UserID), which is
// indistinguishable from the unauthenticated/system pseudo-actor that
// requireGranterHoldsRolePermissions deliberately exempts from the
// escalation-by-proxy ceiling. #2495: this path previously called the
// 4-argument ApproveAccessRequest wrapper, which hardcoded approverMachineID=0,
// so every machine approver was reported to that ceiling as "the trusted system
// pseudo-actor" and the ceiling was skipped outright. Nothing exploited it only
// because the per-item authorization below was the user-only Authorize against
// approverID=0, which no role resolution can satisfy — so the feature was
// simultaneously broken for machine identities and one line away from being a
// ceiling bypass. See internal/core/bulk_access_request_machine_actor_test.go.
func (k *KeyorixCore) BulkApproveAccessRequests(ctx context.Context, requestIDs []uint, approverID, approverMachineID uint) (*BulkApproveResult, error) {
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

	actorType, principalID := approverPrincipal(approverID, approverMachineID)
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
		//
		// #2495: AuthorizePrincipal, not the user-only Authorize. The route gate is
		// already actor-aware (RequireScopedPermission → AuthorizePrincipal), so a
		// machine identity holding roles.assign reaches this handler; resolving its
		// authority as if it were user 0 denied every item unconditionally.
		if allowed, authErr := k.AuthorizePrincipal(ctx, actorType, principalID, permRolesAssign,
			Scope{ProjectID: req.ProjectID}); authErr != nil || !allowed {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "permission denied",
			})
			continue
		}
		// Delegate to existing single-request logic (carries all validation).
		// grantedRole="" → falls back to the request's SuggestedRole.
		_, approveErr := k.ApproveAccessRequestWithExpiry(ctx, req.ProjectID, id, approverID, approverMachineID, "", 0)
		if approveErr != nil {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     approveErr.Error(),
			})
			continue
		}
		result.Approved = append(result.Approved, id)
	}
	// Written unconditionally: ApproveAccessRequest audits each individual
	// approval, but a batch where every item fails (or an empty/all-not-found
	// batch) would otherwise leave no trail that this bulk operation was
	// attempted (F5, audit-completeness campaign).
	k.writeAuditEvent(ctx, "access_request.bulk_approve_attempted", actorPtr(approverID), nil,
		fmt.Sprintf("bulk-approve attempted for %d access request(s): %d approved, %d failed",
			len(requestIDs), len(result.Approved), len(result.Failed)))
	return result, nil
}

// ── Bulk reject ───────────────────────────────────────────────────────────────

// BulkRejectAccessRequests rejects multiple pending access requests with a
// shared reason on behalf of the (approverID, approverMachineID) principal. Each
// request is attempted independently; per-item failures are collected rather
// than aborting the whole batch.
//
// The function delegates to the existing RejectAccessRequest per item so all
// invariants (state check, etc.) are enforced exactly once.
//
// approverMachineID: see BulkApproveAccessRequests. #2495 — rejection has no
// privilege ceiling to skip (nothing is granted), but it had the same two
// consequences: a machine identity holding roles.assign could not reject
// anything, and the ResolvedByMachineIdentityID attribution column #1573 added
// was written as 0, so the audit trail could not say which machine rejected.
func (k *KeyorixCore) BulkRejectAccessRequests(ctx context.Context, requestIDs []uint, approverID, approverMachineID uint, reason string) (*BulkRejectResult, error) {
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

	actorType, principalID := approverPrincipal(approverID, approverMachineID)
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
		if allowed, authErr := k.AuthorizePrincipal(ctx, actorType, principalID, permRolesAssign,
			Scope{ProjectID: req.ProjectID}); authErr != nil || !allowed {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     "permission denied",
			})
			continue
		}
		_, rejectErr := k.RejectAccessRequest(ctx, req.ProjectID, id, approverID, approverMachineID, reason)
		if rejectErr != nil {
			result.Failed = append(result.Failed, BulkAccessError{
				RequestID: id,
				Error:     rejectErr.Error(),
			})
			continue
		}
		result.Rejected = append(result.Rejected, id)
	}
	// Written unconditionally, same reasoning as BulkApproveAccessRequests'
	// own summary event above (F5, audit-completeness campaign): a sibling of
	// bulk-approve with the identical empty/all-failed trail gap.
	k.writeAuditEvent(ctx, "access_request.bulk_reject_attempted", actorPtr(approverID), nil,
		fmt.Sprintf("bulk-reject attempted for %d access request(s): %d rejected, %d failed",
			len(requestIDs), len(result.Rejected), len(result.Failed)))
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
	k.writeAuditEvent(ctx, "rejection_reason_template.created", actorPtr(createdBy), nil,
		fmt.Sprintf("rejection reason template %q created", name))
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
