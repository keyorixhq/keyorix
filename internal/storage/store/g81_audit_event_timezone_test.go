// g81_audit_event_timezone_test.go — regression coverage for G81's AuditEvent
// member (#1492): this codebase previously fixed a GORM/SQLite timezone-
// comparison bug (mixed UTC/local time.Time values break SQLite's
// string-based time comparisons) by adding UTC-normalizing BeforeSave hooks
// to the affected models (MFAStepupToken, MFAStepUpGrant, UserRole,
// GroupRole, DynamicSecretLease), but AuditEvent was never given one — and
// its EventTime is exactly the field GetAuditLogs' event_time >= / <= range
// filter depends on comparing correctly. This is the third recurrence of the
// same bug class.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLogAuditEvent_NonUTCEventTimeStoredAsUTC pins the write half of G81 for
// AuditEvent: an event logged with an EventTime constructed in a non-UTC
// local timezone (e.g. a server running with TZ set) must be persisted and
// read back as UTC, with the instant preserved. This also confirms the hook
// actually fires on LogAuditEvent — the single write funnel for
// audit_events (see BeforeSave's doc comment).
func TestLogAuditEvent_NonUTCEventTimeStoredAsUTC(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC-7", -7*60*60)
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, nonUTC)

	tr := true
	event := &models.AuditEvent{
		EventType: "auth.login", Description: "g81-utc", Success: &tr,
		EventTime: at, ActorType: "user",
	}
	require.NoError(t, ls.LogAuditEvent(ctx, event))
	assert.Equal(t, time.UTC, event.EventTime.Location(), "event_time must be stored in UTC")
	assert.True(t, event.EventTime.Equal(at), "the instant must be preserved even though the zone changed")

	var reloaded models.AuditEvent
	require.NoError(t, ls.db.First(&reloaded, event.ID).Error)
	assert.Equal(t, time.UTC, reloaded.EventTime.Location())
	assert.True(t, reloaded.EventTime.Equal(at))
}

// TestVerifyAuditChain_ValidatesRowWithNonUTCEventTime confirms the hook does
// not break tamper-evidence: EntryHash is computed by LogAuditEvent before
// BeforeSave mutates EventTime (see local_audit_chain.go:187), and
// computeAuditEntryHash encodes EventTime as UnixMicro() — location-
// independent — so a row written through the hook must still verify, both
// alone and chained with a second row.
func TestVerifyAuditChain_ValidatesRowWithNonUTCEventTime(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()
	nonUTC := time.FixedZone("UTC+9", 9*60*60)
	at := time.Now().In(nonUTC)

	tr := true
	e1 := &models.AuditEvent{
		EventType: "auth.login", Description: "g81-chain-1", Success: &tr,
		EventTime: at, ActorType: "user",
	}
	require.NoError(t, ls.LogAuditEvent(ctx, e1))

	v, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify for a row written through the UTC hook: %s", v.Reason)
	assert.Equal(t, int64(1), v.ChainedEvents)

	e2 := &models.AuditEvent{
		EventType: "secret.read", Description: "g81-chain-2", Success: &tr,
		EventTime: at.Add(time.Second), ActorType: "user",
	}
	require.NoError(t, ls.LogAuditEvent(ctx, e2))
	assert.Equal(t, e1.EntryHash, e2.PrevHash, "chain linkage must hold across hook-normalized rows")

	v2, err := ls.VerifyAuditChain(ctx, nil)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "2-row chain must verify: %s", v2.Reason)
	assert.Equal(t, int64(2), v2.ChainedEvents)
}

// TestGetAuditLogs_RangeQuery_FindsRowWithNonUTCEventTime is the regression
// test for the live bug this change fixes (not a theoretical hazard): an
// event is written with EventTime expressed in a non-UTC local zone (as
// every real write site's bare time.Now() would produce on a server process
// not pinned to TZ=UTC), then queried through GetAuditLogs with a UTC
// RFC3339 window — the exact shape internal/core/audit_search.go produces
// via time.Parse(time.RFC3339, "...Z") for a client-supplied filter. Without
// the BeforeSave hook, SQLite's string-based time comparison misses the row
// even though both sides denote the same instant (confirmed by temporarily
// reverting the hook and re-running this test during development — it fails
// with total=0 without the hook, and passes with it; the other two tests in
// this file fail even harder without the hook, with a hard Scan error reading
// the row back at all — "unsupported Scan, storing driver.Value type string
// into type *time.Time" — since modernc.org/sqlite's driver can't parse every
// offset representation it itself wrote back into a Go time.Time).
func TestGetAuditLogs_RangeQuery_FindsRowWithNonUTCEventTime(t *testing.T) {
	ls := newAuditChainTestStore(t)
	ctx := context.Background()

	loc, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	instant := time.Date(2026, 8, 20, 14, 0, 0, 0, time.UTC)
	localRepresentation := instant.In(loc)

	tr := true
	event := &models.AuditEvent{
		EventType: "auth.login", Description: "g81-range", Success: &tr,
		EventTime: localRepresentation, ActorType: "user",
	}
	require.NoError(t, ls.LogAuditEvent(ctx, event))

	start := instant.Add(-time.Minute)
	end := instant.Add(time.Minute)
	events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{StartTime: &start, EndTime: &end})
	require.NoError(t, err)
	require.Equal(t, int64(1), total, "row bracketing the instant must be found by a same-instant UTC range filter")
	require.Len(t, events, 1)
	assert.Equal(t, event.ID, events[0].ID)
}
