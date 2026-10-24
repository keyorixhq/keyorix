package core

import (
	"context"
	"fmt"
)

// EventCryptoInventoryRead is audited on every successful read of the crypto
// inventory / CBOM (RD-CBOM-1). The inventory discloses key locations, algorithms
// and expiry dates, so who read it, and in which format, belongs in the trail.
const EventCryptoInventoryRead = "compliance.crypto_inventory_read"

// LogCryptoInventoryRead records one inventory read. actorID is the requesting
// caller (0 = none). The description carries counts only, never asset detail.
func (c *KeyorixCore) LogCryptoInventoryRead(ctx context.Context, actorID uint, format string, total, quantumVulnerable int) {
	c.writeAuditEvent(ctx, EventCryptoInventoryRead, actorPtr(actorID), nil,
		fmt.Sprintf("crypto inventory read: format=%s assets=%d quantum_vulnerable=%d", format, total, quantumVulnerable))
}
