// shares_wire.go — snake_case wire type for internal/storage/models.ShareRecord
// (no json tags at all — wire keys were the bare Go field names). See
// docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md.
package handlers

import (
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type shareRecordWire struct {
	ID          uint       `json:"id"`
	SecretID    uint       `json:"secret_id"`
	OwnerID     uint       `json:"owner_id"`
	RecipientID uint       `json:"recipient_id"`
	IsGroup     bool       `json:"is_group"`
	Permission  string     `json:"permission"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func newShareRecordWire(s *models.ShareRecord) shareRecordWire {
	return shareRecordWire{
		ID:          s.ID,
		SecretID:    s.SecretID,
		OwnerID:     s.OwnerID,
		RecipientID: s.RecipientID,
		IsGroup:     s.IsGroup,
		Permission:  s.Permission,
		ExpiresAt:   s.ExpiresAt,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}

func newShareRecordWireList(shares []*models.ShareRecord) []shareRecordWire {
	out := make([]shareRecordWire, 0, len(shares))
	for _, s := range shares {
		out = append(out, newShareRecordWire(s))
	}
	return out
}
