package core

// export_audit_test.go — AUDIT-FAILCLOSED-SECRETS-1 (#4721): the scheduled evidence
// export and the per-secret access-log export are recorded before delivery,
// fail-closed. Red on main: the scheduled export wrote its row AFTER delivery with
// the result discarded (the outage leg found the pack on disk and the webhook
// called), and the access-log export wrote no row at all.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestExportComplianceEvidence_RefusedRowDeliversNothing(t *testing.T) {
	t.Parallel()
	c, db, _ := newEvidenceExportCore(t)
	c.storage = hooked(store.NewLocalStorage(db), &storeHooks{
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if e.EventType == "compliance.evidence_exported" {
				return fmt.Errorf("fault-injected: %s audit write failed", e.EventType)
			}
			return next.LogAuditEvent(ctx, e)
		},
	})
	fwd := &fakeEvidenceForwarder{}
	c.SetEvidenceForwarder(fwd)
	dir := t.TempDir()

	_, err := c.ExportComplianceEvidence(context.Background(), dir)
	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	assert.Zero(t, fwd.calls, "a pack whose export is not on record must not be forwarded")
	entries, rerr := os.ReadDir(dir)
	require.NoError(t, rerr)
	assert.Empty(t, entries, "a pack whose export is not on record must not be written")
}

func TestExportComplianceEvidence_DeliveryFailureIsRecorded(t *testing.T) {
	t.Parallel()
	c, db, _ := newEvidenceExportCore(t)
	c.SetEvidenceForwarder(&fakeEvidenceForwarder{err: errors.New("boom")})
	_, err := c.ExportComplianceEvidence(context.Background(), t.TempDir())
	require.NoError(t, err, "a file was written, so a webhook failure is non-fatal")
	for _, evt := range []string{"compliance.evidence_exported", "compliance.evidence_delivery_failed"} {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", evt).Count(&n).Error)
		assert.EqualValues(t, 1, n, evt)
	}
}

func TestExportSecretAccessLog_RecordedBeforeDelivery(t *testing.T) {
	outageBackends(t, func(t *testing.T, w *outageWorld) {
		s := w.secret("acclog-export")
		data, _, err := w.c.ExportSecretAccessLog(context.Background(), ActorTypeUser, w.f.adminID, s.ID, ExportFormatCSV)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.EqualValues(t, 1, w.auditRows("secret.access_log_exported", s.ID))

		w.outage.arm("secret.access_log_exported")
		data, _, err = w.c.ExportSecretAccessLog(context.Background(), ActorTypeUser, w.f.adminID, s.ID, ExportFormatJSON)
		fired := w.outage.fired()
		w.outage.arm("")
		require.Positive(t, fired)
		require.ErrorIs(t, err, ErrMutationAuditUnavailable)
		require.Nil(t, data, "a refused export returns no history")
		require.EqualValues(t, 1, w.auditRows("secret.access_log_exported", s.ID))
	})
}
