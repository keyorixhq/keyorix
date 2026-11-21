package core

import (
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// TestSQLiteNormalReadAuditEventTypes_MatchCore: the event types whose
// successful rows may commit on SQLite's synchronous=NORMAL read-audit
// connection (ADR-112 Amendment 7) are exactly the value-disclosure types
// Amendment 4 skips. A new disclosure type added here must reach the store's
// set too, and the store's set must never hold a type that is not a value
// read (a mutation type there would put that mutation's audit row on NORMAL).
func TestSQLiteNormalReadAuditEventTypes_MatchCore(t *testing.T) {
	var coreTypes []string
	for eventType := range successfulValueReadEventTypes {
		coreTypes = append(coreTypes, eventType)
	}
	slices.Sort(coreTypes)
	require.Equal(t, coreTypes, store.SQLiteNormalReadAuditEventTypes())
}
