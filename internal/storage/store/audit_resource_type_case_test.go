package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #4090: the resource-type filter is a LIKE prefix on event_type. SQLite's LIKE
// folds ASCII case and Postgres's does not, so "Secret" matched secret.read on
// SQLite only. Both backends now answer the same.
func testAuditResourceTypeCase(t *testing.T, chain func(*testing.T, int) (*LocalStorage, []*models.AuditEvent)) {
	ls, rows := chain(t, 1)
	require.Equal(t, "secret.read", rows[0].EventType)
	for term, want := range map[string]int64{
		"secret": 1, "Secret": 1, "SECRET": 1, "sEcReT": 1,
		"Secre": 0, "key": 0, "secret%": 0,
		"Key": 0, // Kelvin sign: not folded onto "k"
	} {
		events, total, err := ls.GetAuditLogs(context.Background(), &storage.AuditFilter{ResourceType: &term})
		require.NoError(t, err)
		assert.Equal(t, want, total, "resource_type %q", term)
		assert.Len(t, events, int(want), "resource_type %q", term)
	}
}

func TestGetAuditLogs_ResourceTypeIsCaseInsensitive(t *testing.T) {
	testAuditResourceTypeCase(t, segmentChain)
}

func TestGetAuditLogs_ResourceTypeIsCaseInsensitive_Postgres(t *testing.T) {
	testAuditResourceTypeCase(t, pgSegmentChain)
}
