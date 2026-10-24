package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1: a recover-admin attempt with a wrong
// recovery key left no trace in the audit chain (only the operator's own
// terminal saw "recovery key does not match"), unlike every other
// authentication failure here (auth.login_failed beside auth.login). Someone
// with host access trying keys against an admin account must be visible to an
// auditor. The event names the host user and target and never the key typed.
func TestPerformRecoverAdmin_WrongKeyIsAudited(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-wrongkey", "admin-wrongkey@example.com", "OldPassw0rd!")
	_ = seedRecoveryKey(t, ctx, store)

	attempt, err := recoverykey.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), attempt, false); err == nil {
		t.Fatal("expected the wrong key to be refused")
	}

	action := "admin.recover_admin_failed"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want exactly 1 %s audit event for the refused attempt, got %d", action, len(events))
	}
	ev := events[0]
	if ev.Success == nil || *ev.Success {
		t.Errorf("Success = %v, want false", ev.Success)
	}
	if ev.UserID == nil || *ev.UserID != user.ID {
		t.Errorf("UserID = %v, want the target %d", ev.UserID, user.ID)
	}
	if !strings.Contains(ev.Description, "did not match") || !strings.Contains(ev.Description, "host user") {
		t.Errorf("description does not say what failed and who ran it: %q", ev.Description)
	}
	normalized := recoverykey.Normalize(attempt)
	for _, leak := range []string{attempt, normalized, normalized[:10], recoverykey.Hash(attempt)} {
		if strings.Contains(ev.Description, leak) {
			t.Errorf("description carries (part of) the attempted key or its hash %q: %q", leak, ev.Description)
		}
	}

	ok := "admin.recover_admin"
	if done, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &ok, PageSize: 10}); err != nil || len(done) != 0 {
		t.Errorf("a refused attempt was recorded as a recovery: %d event(s), err %v", len(done), err)
	}
}
