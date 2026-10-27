package storage

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrMFAResetRequestNotFound: no MFA reset request has that id.
var ErrMFAResetRequestNotFound = errors.New("MFA reset request not found")

// MFAResetStore is the Storage slice for administrator MFA resets
// (RECOVERY-MFA-RESET-1). MFAStore embeds it.
type MFAResetStore interface {
	// SetUserMFAEnrolmentRequired sets or clears users.mfa_enrolment_required.
	SetUserMFAEnrolmentRequired(ctx context.Context, userID uint, required bool) error
	CreateMFAResetRequest(ctx context.Context, r *models.MFAResetRequest) (*models.MFAResetRequest, error)
	// GetMFAResetRequest returns ErrMFAResetRequestNotFound (wrapped) for an
	// unknown id.
	GetMFAResetRequest(ctx context.Context, id uint) (*models.MFAResetRequest, error)
	// ListMFAResetRequests returns requests newest first; pendingOnly keeps rows
	// still in status pending (expired ones included: expiry is computed in core).
	ListMFAResetRequests(ctx context.Context, pendingOnly bool) ([]*models.MFAResetRequest, error)
	// DecideMFAResetRequestIfPending moves request id from pending to status
	// (approved or cancelled) in one conditional UPDATE: WHERE status = pending
	// AND expires_at > now. matched=false means it was already decided, or it
	// expired, and nothing was written. This is what makes a request single-use:
	// two concurrent approvals cannot both match.
	DecideMFAResetRequestIfPending(ctx context.Context, id uint, status string, decidedBy uint, now time.Time) (matched bool, err error)
}
