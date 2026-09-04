// local_invitations.go — project invitations + access requests persistence (ADR-024).
//
// For the remote (HTTP) equivalent see remote_invitations.go.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// invitationStatePending / accessRequestStatePending mirror the "pending" state
// literal from internal/core (invitations.go's InvitationPending /
// AccessRequestPending). Duplicated here rather than imported — storage must not
// depend on core — matching the existing accessReviewCampaignOpen /
// accessReviewItemPending convention in local_access_review_campaigns.go. Every
// mutation of a ProjectInvitation or AccessRequest transitions FROM pending (see
// invitations.go), so gating the write on the persisted row still being pending is
// sufficient to guard every transition, not just a specific one.
const (
	invitationStatePending    = "pending"
	accessRequestStatePending = "pending"
)

// --- Project invitations ---

func (ls *LocalStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	if err := ls.db.WithContext(ctx).Create(inv).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return inv, nil
}

func (ls *LocalStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	var inv models.ProjectInvitation
	if err := ls.db.WithContext(ctx).First(&inv, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &inv, nil
}

// UpdateProjectInvitation persists an invitation state transition with a
// conditional UPDATE (`WHERE id = ? AND state = 'pending'`), not the prior
// unconditional Save (#412). A bare Save let an admin's RevokeInvitation and a
// concurrent holder's completeInvitationAccept race: both read the same pending
// row, both mutated it in memory, and whichever Save landed second silently
// clobbered the other's transition — an admin's revoke could be undone by an
// in-flight accept, or vice versa, with no error on either side. Gating the write
// on the row's CURRENT persisted state still being pending closes that: whichever
// write lands first wins (RowsAffected==1); the loser's UPDATE matches zero rows
// and is told so via the bool, instead of silently overwriting the winner.
func (ls *LocalStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.ProjectInvitation{}).
		Where("id = ? AND state = ?", inv.ID, invitationStatePending).
		Select("*").
		Updates(inv)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	var rows []*models.ProjectInvitation
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// --- Access requests ---

func (ls *LocalStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	if err := ls.db.WithContext(ctx).Create(req).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return req, nil
}

func (ls *LocalStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	var req models.AccessRequest
	if err := ls.db.WithContext(ctx).First(&req, id).Error; err != nil {
		// Was an unconditional "not found" wrap regardless of the underlying
		// error, so a genuine storage failure (e.g. a closed/unreachable DB)
		// read identically to a real not-found to any caller string-matching
		// on it (server/http/handlers' access_request_proxy.go among them).
		// Distinguish genuine not-found (gorm.ErrRecordNotFound) from
		// everything else, matching GetMachineIdentityCredentialByID's
		// already-established fix for the identical bug class.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &req, nil
}

// UpdateAccessRequest persists an access-request state transition with a
// conditional UPDATE (`WHERE id = ? AND state = 'pending'`), not the prior
// unconditional Save (#277). ApproveAccessRequestWithExpiry grants the role BEFORE
// this write lands, so a bare Save racing WithdrawAccessRequest's (or
// RejectAccessRequest's) own read-mutate-Save on the same row let either
// transition silently clobber the other: a withdrawal could land after an
// approval's grant, leaving state=withdrawn (or vice versa, state=approved) with
// no indication anything raced — and, in the approval case, a live role grant
// behind a request that no longer reads as approved. Gating the write on the row's
// CURRENT persisted state still being pending closes that: whichever write lands
// first wins (RowsAffected==1); the loser's UPDATE matches zero rows and is told
// so via the bool, so it can react (e.g. revoke the grant it just made) instead of
// silently overwriting the winner.
func (ls *LocalStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.AccessRequest{}).
		Where("id = ? AND state = ?", req.ID, accessRequestStatePending).
		Select("*").
		Updates(req)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	var rows []*models.AccessRequest
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	// DoNothing on conflict so a duplicate (request_id, approver_id) — e.g. two
	// concurrent approvals from the same approver racing past the app-level dedup —
	// is a benign no-op rather than a unique-violation error. The unique index keeps
	// the dual-control count honest (one row per distinct approver); this just makes
	// the losing racer idempotent. Driver-agnostic (SQLite + Postgres).
	if err := ls.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(a).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	var rows []*models.AccessRequestApproval
	err := ls.db.WithContext(ctx).
		Where("request_id = ?", requestID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}
