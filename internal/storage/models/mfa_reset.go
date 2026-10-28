package models

import "time"

// MFA reset request states (RECOVERY-MFA-RESET-1). "expired" is not stored: a
// pending row whose ExpiresAt has passed reads as expired and can no longer be
// decided.
const (
	MFAResetStatusPending   = "pending"
	MFAResetStatusApproved  = "approved"
	MFAResetStatusCancelled = "cancelled"
)

// MFAResetRequest is one two-admin MFA reset (docs/design/recovery-options.md
// §1, option B): admin RequestedBy asks for the second factor of TargetUserID
// to be reset, and a DIFFERENT global admin decides it. The request moves out
// of pending exactly once (DecideMFAResetRequestIfPending), so an approved
// request cannot be approved again.
type MFAResetRequest struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	TargetUserID uint   `gorm:"index;not null" json:"target_user_id"`
	RequestedBy  uint   `gorm:"not null" json:"requested_by"`
	Reason       string `json:"reason"`
	// VerifiedBy is how the requester confirmed the target's identity:
	// in_person | video | ticket | other. Evidence is free text (a ticket id,
	// who was on the call).
	VerifiedBy string     `json:"verified_by"`
	Evidence   string     `json:"evidence,omitempty"`
	Status     string     `gorm:"index;not null;default:'pending'" json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `gorm:"index" json:"expires_at"`
	DecidedBy  uint       `json:"decided_by,omitempty"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
}
