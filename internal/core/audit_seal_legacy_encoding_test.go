package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// A row hashed under the pre-#1452 encoding is an upgrade step that was not run,
// not a loss: accept-loss refuses it with the plain-words migration hint. The
// choice is made from the stored row, never from the verifier's reason text.
func TestAuditSeal_RefusesLegacyEncodedRowAsNotALoss(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		var row models.AuditEvent
		require.NoError(t, e.db.First(&row, 4).Error)
		legacy := store.ComputeAuditEntryHashPre1452(&row, row.PrevHash)
		require.NoError(t, e.db.Model(&models.AuditEvent{}).Where("id = ?", 4).Update("entry_hash", legacy).Error)

		ok, err := e.c.auditEventIsPre1452Encoded(t.Context(), 4)
		require.NoError(t, err)
		assert.True(t, ok)
		sealRefused(t, e.c, sealReq(4), "old audit-hash format")
	})
}

// A modified row (matches neither encoding) is not classed as legacy and keeps
// its own refusal.
func TestAuditSeal_ModifiedRowIsNotLegacyEncoded(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		tamperDescription(t, e.db, 4)

		ok, err := e.c.auditEventIsPre1452Encoded(t.Context(), 4)
		require.NoError(t, err)
		assert.False(t, ok)
		sealRefused(t, e.c, sealReq(4), "modified")

		ok, err = e.c.auditEventIsPre1452Encoded(t.Context(), 999999)
		require.NoError(t, err)
		assert.False(t, ok, "a missing row is not legacy-encoded")
	})
}

// The core copy of the frozen encoder must equal the store's and auditverify's.
func TestAuditEntryHashPre1452_MatchesStoreAndAuditverify(t *testing.T) {
	uid, pid, ok := uint(7), uint(3), true
	e := &models.AuditEvent{
		ID: 9, EventType: "secret.read", UserID: &uid, ProjectID: &pid, IPAddress: "10.0.0.1",
		Description: "a\x00bc", Success: &ok, EventTime: time.Date(2026, 8, 1, 12, 0, 0, 123456000, time.UTC),
		Diff: `{"k":1}`, ActorType: "user",
	}
	got := auditEntryHashPre1452(e, "prev")
	assert.Equal(t, store.ComputeAuditEntryHashPre1452(e, "prev"), got)

	u64 := func(p *uint) *uint64 {
		if p == nil {
			return nil
		}
		v := uint64(*p)
		return &v
	}
	row := &auditverify.AuditEventRow{
		ID: uint64(e.ID), EventType: e.EventType, UserID: u64(e.UserID), ProjectID: u64(e.ProjectID),
		IPAddress: e.IPAddress, Description: e.Description, Success: e.Success, EventTime: e.EventTime,
		Diff: e.Diff, ActorType: e.ActorType,
	}
	assert.Equal(t, auditverify.ComputeEntryHashPre1452(row, "prev"), got)
}
