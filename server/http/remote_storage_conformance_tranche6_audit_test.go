// remote_storage_conformance_tranche6_audit_test.go — issue #1808, closing tranche.
//
// Covers the one method tranche 5 (#1834) deliberately left uncovered:
// GetAuditLogs. #1834 found that the "logs"-vs-"events" envelope-key fix
// (#1832) was real, but unmarshaling directly into the untagged
// []*models.AuditEvent still silently zeroed EventType/EventTime/ActorType
// (the server's snake_case keys never fold onto the bare Go field names).
// That's now fixed in internal/storage/store/remote_audit.go via a properly
// tagged auditLogEntryWire type — see its doc comment for exactly which
// fields AuditLogEntry (a UI-oriented projection, not the raw row) can and
// cannot carry. This test proves the fix and pins the remaining, structural
// (not wire-format) gap so a future regression can't silently widen it.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestConformance_GetAuditLogs(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	seed := func(eventType, description string, at time.Time) {
		require.NoError(t, h.ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType:   eventType,
			Description: description,
			EventTime:   at,
			UserID:      &h.adminUserID,
			ProjectID:   &h.projectID,
		}))
	}

	// StartTime is set a second before the first seeded event, not equal to it:
	// an inclusive range filter's boundary condition (event_time >= StartTime)
	// depends on SQLite comparing two independently-formatted TEXT timestamps,
	// and asserting exact-boundary inclusion makes the test's own premise
	// fragile to formatting precision, not just the behavior under test. A
	// one-second margin still proves the filter includes events "at or after"
	// StartTime without relying on exact string equality at the boundary.
	event1Time := time.Now().UTC().Add(-time.Hour)
	base := event1Time.Add(-time.Second)
	action := "conformance.tranche6.audit.marker"
	seed(action, "conformance tranche6 event 1", event1Time)
	seed(action, "conformance tranche6 event 2", event1Time.Add(time.Minute))
	// A distractor event with a different action, in range, to prove the
	// Action filter is actually applied server-side (not just "return
	// everything and trust the caller").
	seed("conformance.tranche6.audit.distractor", "should not match", event1Time.Add(2*time.Minute))

	filter := &corestorage.AuditFilter{
		Action:    &action,
		StartTime: &base,
		Page:      1,
		PageSize:  50,
	}

	localEvents, localTotal, err := h.ls.GetAuditLogs(ctx, filter)
	require.NoError(t, err)
	require.Len(t, localEvents, 2, "sanity: the local seed must produce exactly the 2 matching events")
	assert.EqualValues(t, 2, localTotal)

	remoteEvents, remoteTotal, err := h.rs.GetAuditLogs(ctx, filter)
	require.NoError(t, err)
	assert.EqualValues(t, 2, remoteTotal,
		"RemoteStorage.GetAuditLogs must report the real matching count, not a stale/mismatched one")
	require.Len(t, remoteEvents, 2,
		"the historical defect class: a correct-looking total beside an empty (or wrong-length) event list")

	// GetAuditLogs' response is a UI-oriented projection (AuditLogEntry), not
	// the raw row -- it never carries UserID/SecretNodeID/ProjectID/IPAddress/
	// Success/MachineIdentityID/the ADR-029 hash-chain fields at all (see
	// auditLogEntryWire's doc comment in remote_audit.go). Asserting equality
	// on those here would either fail forever or force a fake pass; instead,
	// assert equality on exactly the fields the wire format actually carries,
	// keyed by ID so seed order doesn't matter.
	byID := func(events []*models.AuditEvent, id uint) *models.AuditEvent {
		for _, e := range events {
			if e.ID == id {
				return e
			}
		}
		t.Fatalf("event %d not found in result set", id)
		return nil
	}
	for _, le := range localEvents {
		re := byID(remoteEvents, le.ID)
		assert.Equal(t, le.EventType, re.EventType, "EventType must round-trip over the wire")
		assert.WithinDuration(t, le.EventTime, re.EventTime, time.Second, "EventTime must round-trip over the wire")
		assert.Equal(t, le.Description, re.Description, "Description must round-trip over the wire")
		assert.Equal(t, le.ActorType, re.ActorType, "ActorType must round-trip over the wire")
		assert.Equal(t, le.Impersonation, re.Impersonation, "Impersonation must round-trip over the wire")

		// Documented, structural (not wire-bug) gaps: the server-side
		// AuditLogEntry projection never sends these, so they must be zero on
		// every RemoteStorage-returned event, not equal to the local value.
		assert.Nil(t, re.UserID, "UserID is not carried by GET /api/v1/audit/logs's response shape")
		assert.Nil(t, re.ProjectID, "ProjectID is not carried by GET /api/v1/audit/logs's response shape")
		assert.Nil(t, re.SecretNodeID, "SecretNodeID is not carried by GET /api/v1/audit/logs's response shape")
		assert.Empty(t, re.IPAddress, "IPAddress is not carried by GET /api/v1/audit/logs's response shape")
	}

	// Negative case: a filter matching nothing must come back empty, not error
	// and not (via a stale cache or a dropped filter) return unrelated events.
	noMatch := "conformance.tranche6.audit.no-such-action"
	emptyFilter := &corestorage.AuditFilter{Action: &noMatch, Page: 1, PageSize: 50}
	remoteEmpty, remoteEmptyTotal, err := h.rs.GetAuditLogs(ctx, emptyFilter)
	require.NoError(t, err)
	assert.Zero(t, remoteEmptyTotal)
	assert.Empty(t, remoteEmpty)
}
