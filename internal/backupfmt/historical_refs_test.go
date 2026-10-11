package backupfmt

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCheckDanglingReferences_SkipsExactlyTheHistoricalColumns (#3085): an
// audit row that names a purged secret is not dangling, while a mutable row
// naming the same missing secret still is. The audit_events edge must exist in
// the derived reference edges, otherwise the skip below would pass vacuously.
func TestCheckDanglingReferences_SkipsExactlyTheHistoricalColumns(t *testing.T) {
	edges, err := referenceEdges()
	require.NoError(t, err)
	var derived bool
	for _, e := range edges {
		if e.ChildTable == "audit_events" && e.ChildColumn == "secret_node_id" && e.ParentTable == "secret_nodes" {
			derived = true
		}
	}
	require.True(t, derived, "audit_events.secret_node_id -> secret_nodes must be a derived edge, or the skip proves nothing")

	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.AuditEvent{}, &models.SecretAccessLog{}))
	missing := uint(99999)
	require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.read", SecretNodeID: &missing}).Error)
	require.NoError(t, db.Create(&models.SecretAccessLog{SecretNodeID: missing, Action: "read"}).Error)

	got, err := CheckDanglingReferences(db, []any{&models.SecretNode{}, &models.AuditEvent{}, &models.SecretAccessLog{}})
	require.NoError(t, err)
	require.Len(t, got, 1, "only the mutable secret_access_logs row is dangling: %+v", got)
	require.Equal(t, "secret_access_logs", got[0].Table)
	require.Equal(t, "secret_node_id", got[0].Column)
	require.Equal(t, missing, got[0].MissingID)
}
