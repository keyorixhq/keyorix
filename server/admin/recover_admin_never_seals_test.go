package admin

// recover-admin verifies first and records a broken chain in its own event, but
// never seals the break (docs/design/recovery-options.md §2 "recover-admin";
// AUDIT-ACCEPT-LOSS-1): accepting a loss is the separate, audited
// `admin audit accept-loss`, so a lockout recovery can never bless tampering.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

func TestPerformRecoverAdmin_NeverSealsALoss(t *testing.T) {
	ctx := context.Background()
	store, dsn := newRecoverAdminTestStoreWithDSN(t)
	user := seedAdminUser(t, ctx, store, "admin6", "admin6@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)
	ok := true
	for i := range 3 {
		if err := store.LogAuditEvent(ctx, &models.AuditEvent{
			EventType: "test.seed", Description: fmt.Sprintf("seed %d", i), Success: &ok, ActorType: "test", EventTime: time.Now(),
		}); err != nil {
			t.Fatalf("seed audit event: %v", err)
		}
	}
	rawDB, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := rawDB.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	// A real loss: the middle seed row is gone.
	if err := rawDB.Exec("DELETE FROM audit_events WHERE id = (SELECT id FROM audit_events WHERE description = 'seed 1')").Error; err != nil {
		t.Fatalf("delete audit row: %v", err)
	}
	before, err := store.VerifyAuditChain(ctx, nil)
	if err != nil || before.Valid || before.FirstBrokenID == nil {
		t.Fatalf("precondition: the chain reads broken, got %+v (%v)", before, err)
	}

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}
	if !summary.auditChainBroken || summary.auditChainFirstBrokenID != *before.FirstBrokenID {
		t.Errorf("the break must be recorded at #%d, got broken=%v id=%d", *before.FirstBrokenID, summary.auditChainBroken, summary.auditChainFirstBrokenID)
	}

	// This store has no system_metadata table at all (an error, never found).
	if _, found, _ := store.GetSystemMetadata(ctx, "audit_seals"); found {
		t.Errorf("recover-admin wrote a seal record: it must never seal")
	}
	sealEvent := "system.audit_loss_accepted"
	if evs, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &sealEvent, PageSize: 10}); err != nil || len(evs) != 0 {
		t.Errorf("recover-admin appended %d accepted-loss events (err %v): it must never seal", len(evs), err)
	}
	after, err := store.VerifyAuditChain(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if after.Valid || after.FirstBrokenID == nil || *after.FirstBrokenID != *before.FirstBrokenID {
		t.Errorf("the break must still be there at #%d after recover-admin, got %+v", *before.FirstBrokenID, after)
	}
	action := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected the recovery event, got %d (%v)", len(events), err)
	}
	if !strings.Contains(events[0].Description, "ALREADY BROKEN") {
		t.Errorf("the recovery event must record the break, got %q", events[0].Description)
	}
}
