package storage

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AccessStore is the Storage slice for invitations, access requests, access reviews, SoD policies and rejection templates.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type AccessStore interface {
	// Project invitations (ADR-024).
	CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error)
	GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error)
	// UpdateProjectInvitation persists an invitation state transition with a
	// conditional UPDATE (only an invitation whose CURRENT stored state is still
	// "pending" may be transitioned). The bool reports whether the row matched and
	// was updated; false means the invitation was already resolved (accepted,
	// revoked, or expired) by a prior or racing call and this write was rejected,
	// not silently applied (#412).
	UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error)
	ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error)

	// Access requests (ADR-024).
	CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error)
	GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error)
	// UpdateAccessRequest persists an access-request state transition with a
	// conditional UPDATE (only a request whose CURRENT stored state is still
	// "pending" may be transitioned). The bool reports whether the row matched and
	// was updated; false means the request was already resolved (approved,
	// rejected, withdrawn, or expired) by a prior or racing call and this write was
	// rejected, not silently applied (#277).
	UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error)
	ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error)
	// Access-request approvals (N-of-M dual control). One row per approver sign-off.
	CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error
	ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error)

	// Access-review campaigns (ISO 27001 A.5.18) — periodic recertification cycles
	// and the per-grant items captured within them.
	CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error)
	GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error)
	ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error)
	// GetOpenAccessReviewCampaign returns the project's currently open campaign, or
	// nil if none is open — a targeted single-row lookup for callers (e.g. the
	// recertification scheduler tick, #238) that only need to know whether a review
	// is already in flight, not the project's full historical campaign list.
	GetOpenAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error)
	// GetLatestClosedAccessReviewCampaign returns the project's most recently closed
	// campaign (by CreatedAt), or nil if it has never had one. A targeted
	// ORDER BY ... LIMIT 1 lookup for callers that only need the anchor point for the
	// next recertification due-date, not the entire historical corpus (#238).
	GetLatestClosedAccessReviewCampaign(ctx context.Context, projectID uint) (*models.AccessReviewCampaign, error)
	// UpdateAccessReviewCampaign persists a campaign state transition with a
	// conditional UPDATE (only a campaign whose CURRENT stored state is still "open"
	// may be transitioned). The bool reports whether the row matched and was updated;
	// false means the campaign was already closed (by a prior or racing call) and
	// this write was rejected, not silently applied.
	UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (bool, error)
	CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error
	ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error)
	// CountPendingAccessReviewItems returns the number of items in a campaign still
	// awaiting a decision (decision = "pending"), without loading the item rows
	// themselves — used by the recertification scheduler tick (#238) to size an
	// in-flight campaign's remaining work for a reminder.
	CountPendingAccessReviewItems(ctx context.Context, campaignID uint) (int, error)
	GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error)
	// UpdateAccessReviewItem persists a decision with a conditional UPDATE (only an
	// item whose CURRENT stored decision is still "pending", in a campaign whose
	// CURRENT stored state is still "open", may be transitioned). The bool reports
	// whether the row matched and was updated; false means either the item was
	// already decided or the parent campaign was closed (by a prior or racing call)
	// and this write was rejected, not silently applied.
	UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) (bool, error)

	// Separation-of-duties policies (ISO 27001 A.5.3 / SOX) — toxic permission pairs.
	CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error)
	GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error)
	ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error)
	DeleteSoDPolicy(ctx context.Context, id uint) error

	// Rejection reason templates — pre-defined reasons for rejecting access
	// requests. The REST API is the remote surface; these methods only run
	// server-side via LocalStorage.
	CreateRejectionReasonTemplate(ctx context.Context, t *models.RejectionReasonTemplate) error
	ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error)
	DeleteRejectionReasonTemplate(ctx context.Context, id uint) error

	// ListAccessRequestsByIDs returns the access requests matching the given IDs.
	// Used by the bulk-approve/reject operations to pre-fetch all requests in one
	// query and provide per-item errors without N individual GetAccessRequest calls.
	ListAccessRequestsByIDs(ctx context.Context, ids []uint) ([]*models.AccessRequest, error)
}
