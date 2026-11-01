package core

import (
	"context"
	"fmt"
)

// EventCryptoInventoryRead is audited on every successful read of the crypto
// inventory / CBOM (RD-CBOM-1). The inventory discloses key locations, algorithms
// and expiry dates, so who read it, and in which format, belongs in the trail.
const EventCryptoInventoryRead = "compliance.crypto_inventory_read"

// CryptoInventoryAuditUnavailableMessage is the fixed client text of a read
// refused because its audit row could not be recorded.
const CryptoInventoryAuditUnavailableMessage = "could not record the read in the audit log; the inventory was not returned, retry"

// LogCryptoInventoryRead records one inventory read and reports whether it
// landed: audit-before-disclosure (#3716), like the secret-value reads
// (LogSecretReadWithProject). The caller sends the inventory only on nil; an
// unrecorded row is ErrMutationAuditUnavailable (wrapped) and nothing may be
// disclosed. actorID is the requesting caller (0 = none). The description
// carries counts only, never asset detail.
func (c *KeyorixCore) LogCryptoInventoryRead(ctx context.Context, actorID uint, format string, total, quantumVulnerable int) error {
	if !c.writeAuditEventFull(ctx, EventCryptoInventoryRead, actorPtr(actorID), nil, nil, "",
		fmt.Sprintf("crypto inventory read: format=%s assets=%d quantum_vulnerable=%d", format, total, quantumVulnerable)) {
		return fmt.Errorf("%w: audit event %q was not recorded", ErrMutationAuditUnavailable, EventCryptoInventoryRead)
	}
	return nil
}
