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

// AUDIT-REQUEST-ID-2 item 1: storage.AuditFilter.RequestID selects exactly the rows
// stamped with that server-minted id (docs/specs/audit-request-id.md §8).
func TestGetAuditLogs_FilterByRequestID(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC().Add(-time.Hour)
	ok, refused := true, false
	write := func(ctx context.Context, i int, eventType string, success *bool) {
		t.Helper()
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: eventType, Success: success, ActorType: "user",
			EventTime: base.Add(time.Duration(i) * time.Second),
		}))
	}

	const (
		idMutation = "aaaaaaaaaaaaaaaaaaaaaaaa"
		idRefused  = "bbbbbbbbbbbbbbbbbbbbbbbb"
	)
	write(serverRequestCtx(idMutation), 0, "secret.created", &ok)
	write(serverRequestCtx(idMutation), 1, "secret.updated", &ok) // one request, two rows
	write(serverRequestCtx(idRefused), 2, "auth.login_failed", &refused)
	write(context.Background(), 3, "system.tick", &ok) // no request: NULL

	list := func(f storage.AuditFilter) []*models.AuditEvent {
		t.Helper()
		f.PageSize = 50
		events, _, err := ls.GetAuditLogs(context.Background(), &f)
		require.NoError(t, err)
		return events
	}
	eventTypes := func(events []*models.AuditEvent) []string {
		out := make([]string, len(events))
		for i, e := range events {
			out[i] = e.EventType
		}
		return out
	}

	mut := idMutation
	assert.ElementsMatch(t, []string{"secret.created", "secret.updated"}, eventTypes(list(storage.AuditFilter{RequestID: &mut})))

	// A refused request's row (Success=false) carries its id and is found by it.
	ref := idRefused
	got := list(storage.AuditFilter{RequestID: &ref})
	require.Len(t, got, 1)
	assert.Equal(t, "auth.login_failed", got[0].EventType)
	require.NotNil(t, got[0].Success)
	assert.False(t, *got[0].Success)
	require.NotNil(t, got[0].RequestID)
	assert.Equal(t, idRefused, *got[0].RequestID)

	// Exact match only: a prefix, another id and the empty string match nothing, so
	// rows without an id are never returned by a request_id filter.
	for _, v := range []string{idMutation[:12], "cccccccccccccccccccccccc", ""} {
		assert.Empty(t, list(storage.AuditFilter{RequestID: &v}), "request_id=%q", v)
	}

	// It composes with the other predicates.
	action := "secret.updated"
	assert.Equal(t, []string{"secret.updated"}, eventTypes(list(storage.AuditFilter{RequestID: &mut, Action: &action})))

	// No filter: all four rows, the NULL one without an id.
	all := list(storage.AuditFilter{})
	require.Len(t, all, 4)
}
