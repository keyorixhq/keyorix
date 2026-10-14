// audit_list_indexes_test.go — the audit views sort newest-first; the sort must be
// served by an index, not a temp b-tree over the whole table (LIST-ENDPOINTS-1).
package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestAuditEvents_NewestFirstQueriesUseAnIndex(t *testing.T) {
	db := sqlitetest.OpenWithDialector(t, "auditidx_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}))
	// ANALYZE-free: the planner picks the index for an ORDER BY ... LIMIT on its own.
	queries := map[string]string{
		"GET /audit/logs (all events)":       "SELECT * FROM audit_events ORDER BY event_time DESC LIMIT 50",
		"per-secret trail":                   "SELECT * FROM audit_events WHERE secret_node_id = 3 ORDER BY event_time DESC LIMIT 50",
		"per-project view":                   "SELECT * FROM audit_events WHERE project_id = 2 ORDER BY event_time DESC LIMIT 50",
		"event_type filter (via event_time)": "SELECT * FROM audit_events WHERE event_type = 'secret.read' ORDER BY event_time DESC LIMIT 50",
	}
	for name, q := range queries {
		var plan []struct {
			Detail string `gorm:"column:detail"`
		}
		require.NoError(t, db.Raw("EXPLAIN QUERY PLAN "+q).Scan(&plan).Error, name)
		var all []string
		for _, p := range plan {
			all = append(all, p.Detail)
		}
		joined := strings.Join(all, " | ")
		require.NotContains(t, joined, "TEMP B-TREE", fmt.Sprintf("%s sorts the whole table: %s", name, joined))
		require.Contains(t, joined, "USING INDEX", fmt.Sprintf("%s does not use an index: %s", name, joined))
	}
}
