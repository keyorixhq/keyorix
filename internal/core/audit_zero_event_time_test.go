package core

// audit_zero_event_time_test.go — FIX-3088 follow-up. LogAuditEvent never
// defaults EventTime, so an emitter that leaves it unset stored a 0001-01-01
// row; on a non-UTC host that instant's local-mean-time offset is what broke
// audit row 1 across a Postgres backup/restore. The core emit choke point
// (prepareAuditEventForEmit) now defaults it to now, UTC, microsecond-truncated,
// before the storage write hashes the row.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestEmitAudit_ZeroEventTimeIsStoredAsNowAndVerifies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newCheckpointCore(t)
	ok := true

	// One event with an explicit time, so the test also pins that a time the
	// emitter DID set is left alone.
	set := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	require.True(t, c.emitAudit(ctx, &models.AuditEvent{
		EventType: "system.explicit_time", Success: &ok, ActorType: ActorTypeSystem, EventTime: set,
	}))

	before := time.Now().UTC().Truncate(time.Microsecond)
	require.True(t, c.emitAudit(ctx, &models.AuditEvent{
		EventType: "system.no_time", Success: &ok, ActorType: ActorTypeSystem, // EventTime deliberately unset
	}))
	after := time.Now().UTC()

	var rows []models.AuditEvent
	require.NoError(t, db.Order("id").Find(&rows).Error)
	require.Len(t, rows, 2)

	assert.True(t, rows[0].EventTime.Equal(set), "an EventTime the emitter set must be kept as is, got %v", rows[0].EventTime)

	got := rows[1].EventTime
	require.False(t, got.IsZero(), "an event emitted without an EventTime must not be stored with the zero time")
	assert.False(t, got.Before(before) || got.After(after),
		"the defaulted EventTime must be the emit time: got %v, want within [%v, %v]", got, before, after)
	assert.Equal(t, got, got.Truncate(time.Microsecond), "stored at microsecond precision, the chain's hashed form")

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, "verify-audit must pass over the defaulted row: %+v", v)
}
