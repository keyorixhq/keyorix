package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogAuditEvent_SucceedsWithAlreadyCanceledCallerContext is the deterministic,
// non-racy proof that #1650's mechanism fix actually works, not just that the source
// code happens to call auditWriteContext syntactically (see
// audit_write_context_completeness_test.go for that structural check). The original
// bug report reproduced this by racing a client disconnect against a real HTTP
// request's timing window — necessarily probabilistic and slow. Canceling the context
// BEFORE the call even starts removes the timing dependency entirely while exercising
// the identical failure mode: if LogAuditEvent used ctx directly, ls.db.WithContext(ctx)
// would refuse to even begin the transaction, and this write would fail with "context
// canceled" -- exactly the gap #1650 demonstrated live on a real mutation.
func TestLogAuditEvent_SucceedsWithAlreadyCanceledCallerContext(t *testing.T) {
	ls := newAuditChainTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before LogAuditEvent is ever called

	tr := true
	event := &models.AuditEvent{
		EventType: "role.assigned", Description: "canceled-caller-context regression",
		Success: &tr, EventTime: time.Now().UTC(), ActorType: "user",
	}
	err := ls.LogAuditEvent(ctx, event)
	require.NoError(t, err, "an audit write must succeed even when its caller's context was already canceled (#1650) -- a committed mutation must never end up with zero audit record just because the triggering request disconnected")

	logs, total, err := ls.GetAuditLogs(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	assert.Equal(t, "role.assigned", logs[0].EventType)
}
