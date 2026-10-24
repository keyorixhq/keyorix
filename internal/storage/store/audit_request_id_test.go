package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/logging"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// docs/specs/audit-request-id.md: request_id is outside the hash chain, stamped
// only from the server-minted id in the context, and advisory.

func serverRequestCtx(id string) context.Context {
	ctx, h := logging.WithHolder(context.Background())
	h.SetServerRequestID(id)
	return ctx
}

func readRequestIDs(t *testing.T, ls *LocalStorage) []*string {
	t.Helper()
	var rows []struct{ RequestID *string }
	require.NoError(t, ls.db.Raw("SELECT request_id FROM audit_events ORDER BY id").Scan(&rows).Error)
	got := make([]*string, len(rows))
	for i, r := range rows {
		got[i] = r.RequestID
	}
	return got
}

func TestAuditEntryHash_IgnoresRequestID(t *testing.T) {
	tr := true
	uid := uint(7)
	e := &models.AuditEvent{
		EventType: "secret.read", UserID: &uid, Description: "d", Success: &tr,
		EventTime: time.Unix(1_700_000_000, 123_000).UTC(), ActorType: "user", IPAddress: "10.0.0.1",
	}
	without := computeAuditEntryHash(e, auditGenesisHash)
	id := "0123456789abcdef01234567"
	e.RequestID = &id
	assert.Equal(t, without, computeAuditEntryHash(e, auditGenesisHash), "request_id must not be a hash input")

	// The offline verifier's independent implementation agrees (it has no
	// request_id field at all, so equality here pins both sides).
	uid64 := uint64(uid)
	row := &auditverify.AuditEventRow{
		EventType: e.EventType, UserID: &uid64, Description: e.Description, Success: e.Success,
		EventTime: e.EventTime, ActorType: e.ActorType, IPAddress: e.IPAddress,
	}
	assert.Equal(t, without, auditverify.ComputeEntryHash(row, auditGenesisHash))
}

func TestLogAuditEvent_StampsOnlyServerMintedRequestID(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	tr := true
	ev := func(i int) *models.AuditEvent {
		return &models.AuditEvent{EventType: "secret.read", Success: &tr, EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user"}
	}

	// 1. server-minted id in the context: stored.
	require.NoError(t, ls.LogAuditEvent(serverRequestCtx("aaaaaaaaaaaaaaaaaaaaaaaa"), ev(0)))

	// 2. an externally supplied id (SetRequestID, e.g. the recovery fallback): not stored.
	extCtx, h := logging.WithHolder(context.Background())
	h.SetRequestID("client-chosen")
	require.NoError(t, ls.LogAuditEvent(extCtx, ev(1)))

	// 3. a writer that sets RequestID itself, with no request: overwritten to NULL.
	forged := "forged-by-writer"
	e3 := ev(2)
	e3.RequestID = &forged
	require.NoError(t, ls.LogAuditEvent(context.Background(), e3))

	// 4. the transaction-scoped (AUDIT-TX-2, direct) path stamps the same way.
	require.NoError(t, ls.WithTransaction(serverRequestCtx("bbbbbbbbbbbbbbbbbbbbbbbb"), func(tx storage.Storage) error {
		return tx.LogAuditEventWithAccessLog(serverRequestCtx("bbbbbbbbbbbbbbbbbbbbbbbb"), ev(3), nil)
	}))

	got := readRequestIDs(t, ls)
	require.Len(t, got, 4)
	require.NotNil(t, got[0])
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaa", *got[0])
	assert.Nil(t, got[1], "an id that did not come from the server is never stored")
	assert.Nil(t, got[2], "a writer cannot choose request_id")
	require.NotNil(t, got[3])
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbb", *got[3])
}

// A chain mixing NULL and set request ids verifies, and keeps verifying after a
// direct database edit of request_id: the documented advisory status (spec §5).
// If this ever turns red because request_id became a hash input, the spec, the
// schema-epoch reasoning and the offline verifier all have to change with it.
func TestVerifyAuditChain_MixedRequestIDs_AndEditIsUndetected(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	tr := true
	for i := range 4 {
		ctx := context.Background()
		if i%2 == 0 {
			ctx = serverRequestCtx("cccccccccccccccccccccccc")
		}
		require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "secret.read", Success: &tr, EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}))
	}
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, v.Valid)
	require.Equal(t, int64(4), v.ChainedEvents)

	require.NoError(t, ls.db.Exec("UPDATE audit_events SET request_id = 'rewritten' WHERE request_id IS NULL").Error)
	require.NoError(t, ls.db.Exec("UPDATE audit_events SET request_id = NULL WHERE request_id = 'cccccccccccccccccccccccc'").Error)
	v, err = ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "request_id is advisory: editing it is not detected by the chain")
}
