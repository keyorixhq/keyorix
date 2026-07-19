// secret_ownership_history.go — per-secret ownership-transfer chain, derived from
// existing audit_events rows (event_type = "secret.owner_transferred"). No new DB
// table: the data already lives in the audit log written by transferOwnership.
package core

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// OwnershipRecord is one link in a secret's ownership-transfer chain.
type OwnershipRecord struct {
	EventID   uint      `json:"event_id"`
	FromID    uint      `json:"from_id"`    // previous owner user ID
	ToID      uint      `json:"to_id"`      // new owner user ID
	ChangedBy uint      `json:"changed_by"` // actor who performed the transfer (UserID on the audit row)
	ChangedAt time.Time `json:"changed_at"`
	// Description is the full human-readable audit description, preserved as-is for
	// consumers that want more context than the parsed IDs alone.
	Description string `json:"description"`
}

// ownershipDescRe parses the description written by transferOwnership:
//
//	transferred ownership of secret "NAME" from user OLD_ID to user NEW_ID
var ownershipDescRe = regexp.MustCompile(`from user (\d+) to user (\d+)`)

// GetSecretOwnershipHistory returns the chain of ownership transfers for secretID
// in chronological order (oldest first), derived from AuditEvent rows where
// EventType == EventSecretOwnerTransferred. The actor must be able to read the
// secret. An empty slice (not an error) is returned when no transfers have
// occurred yet.
func (c *KeyorixCore) GetSecretOwnershipHistory(ctx context.Context, secretID, actorID uint) ([]OwnershipRecord, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}

	action := EventSecretOwnerTransferred
	// Ascending = true so results are ordered oldest-first (chronological chain).
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		SecretID:  &secretID,
		Action:    &action,
		Ascending: true,
		PageSize:  500,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	records := make([]OwnershipRecord, 0, len(events))
	for _, e := range events {
		rec := OwnershipRecord{
			EventID:     e.ID,
			ChangedAt:   e.EventTime,
			Description: e.Description,
		}
		if e.UserID != nil {
			rec.ChangedBy = *e.UserID
		}
		// Parse "from user X to user Y" from the description.
		if m := ownershipDescRe.FindStringSubmatch(e.Description); len(m) == 3 {
			fromID, err1 := strconv.ParseUint(m[1], 10, 64)
			toID, err2 := strconv.ParseUint(m[2], 10, 64)
			if err1 == nil && err2 == nil {
				rec.FromID = uint(fromID)
				rec.ToID = uint(toID)
			}
		}
		records = append(records, rec)
	}
	return records, nil
}
