package admin

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
)

// suspendBeforeTx wraps store so the target is suspended after recover-admin's
// first read and before its reset transaction starts: the window a live server
// can write in under the admin --force lock bypass.
func suspendBeforeTx(store storage.Storage, userID uint, state string) *storagetest.HookStore {
	return storagetest.Hooked(store, &storagetest.StoreHooks{
		WithTransaction: func(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error {
			if err := next.SetAccountState(ctx, userID, state, time.Now()); err != nil {
				return err
			}
			return next.WithTransaction(ctx, fn)
		},
	})
}

// The blocked-state check is repeated on the row lock inside the reset
// transaction: an account suspended after the first read is refused, nothing
// is reset, and the refusal is audited.
func TestPerformRecoverAdmin_RechecksBlockedStateOnRowLock(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-race", "admin-race@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)
	seedSecondFactors(t, ctx, store, user.ID)
	before, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	_, err = performRecoverAdminOpts(ctx, suspendBeforeTx(store, user.ID, core.AccountSuspended),
		fmt.Sprintf("%d", user.ID), rawKey, false, 0, false)
	if err == nil {
		t.Fatalf("recover-admin lifted a suspension that landed between its read and its transaction")
	}
	if !strings.Contains(err.Error(), "--force-unsuspend") || !strings.Contains(err.Error(), core.AccountSuspended) {
		t.Errorf("error does not name the state and the flag: %v", err)
	}
	assertSecondFactorsIntact(t, ctx, store, user.ID, core.AccountSuspended)
	after, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser after: %v", err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Errorf("password hash changed by a refused run")
	}

	failed := "admin.recover_admin_failed"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &failed, PageSize: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("want 1 %s event, got %d (err %v)", failed, len(events), err)
	}
	if !strings.Contains(events[0].Description, "--force-unsuspend was not given") ||
		!strings.Contains(events[0].Description, strconv.Quote(core.AccountSuspended)) {
		t.Errorf("refusal event does not name the state and why: %q", events[0].Description)
	}
	done := "admin.recover_admin"
	if recovered, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &done, PageSize: 10}); err != nil || len(recovered) != 0 {
		t.Errorf("a refused run was recorded as a recovery: %d event(s), err %v", len(recovered), err)
	}
}

// Under --force-unsuspend the lifted state comes from the locked row, so a
// suspension that landed after the first read is still recorded as lifted.
func TestPerformRecoverAdmin_ForceUnsuspendRecordsStateFoundOnRowLock(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-race-forced", "admin-race-forced@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdminOpts(ctx, suspendBeforeTx(store, user.ID, core.AccountSuspended),
		fmt.Sprintf("%d", user.ID), rawKey, false, 0, true)
	if err != nil {
		t.Fatalf("performRecoverAdminOpts with force: %v", err)
	}
	if summary.liftedState != core.AccountSuspended {
		t.Errorf("liftedState = %q, want %q (the state on the locked row)", summary.liftedState, core.AccountSuspended)
	}
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.AccountState != core.AccountPasswordResetRequired {
		t.Errorf("AccountState = %q, want %q", got.AccountState, core.AccountPasswordResetRequired)
	}
	done := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &done, PageSize: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("want 1 %s event, got %d (err %v)", done, len(events), err)
	}
	if !strings.Contains(events[0].Description, strconv.Quote(core.AccountSuspended)) ||
		!strings.Contains(events[0].Description, "--force-unsuspend lifted that state") {
		t.Errorf("audit event does not record the lifted state: %q", events[0].Description)
	}
}

// An account_state Keyorix never writes fails closed (core.AccountLoginBlocked).
// recover-admin refuses it with a message that says the value is unrecognised,
// not a deliberate block, and the raw value is quoted wherever it is recorded.
func TestPerformRecoverAdmin_UnrecognisedStateIsNamedAndQuoted(t *testing.T) {
	const rawState = `bogus" state`
	quoted := strconv.Quote(rawState)

	t.Run("refused", func(t *testing.T) {
		ctx := context.Background()
		store := newRecoverAdminTestStore(t)
		user := seedAdminUser(t, ctx, store, "admin-odd", "admin-odd@example.com", "OldPassw0rd!")
		rawKey := seedRecoveryKey(t, ctx, store)
		seedSecondFactors(t, ctx, store, user.ID)
		if err := store.SetAccountState(ctx, user.ID, rawState, time.Now()); err != nil {
			t.Fatalf("SetAccountState: %v", err)
		}

		_, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
		if err == nil {
			t.Fatalf("recover-admin reset an account in an unrecognised state without --force-unsuspend")
		}
		if !strings.Contains(err.Error(), "unrecognised account state "+quoted) || strings.Contains(err.Error(), "on purpose") {
			t.Errorf("error does not call the state unrecognised: %v", err)
		}
		assertSecondFactorsIntact(t, ctx, store, user.ID, rawState)

		failed := "admin.recover_admin_failed"
		events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &failed, PageSize: 10})
		if err != nil || len(events) != 1 {
			t.Fatalf("want 1 %s event, got %d (err %v)", failed, len(events), err)
		}
		if !strings.Contains(events[0].Description, "unrecognised account state "+quoted) {
			t.Errorf("refusal event does not quote the unrecognised state: %q", events[0].Description)
		}
	})

	t.Run("forced", func(t *testing.T) {
		ctx := context.Background()
		store := newRecoverAdminTestStore(t)
		user := seedAdminUser(t, ctx, store, "admin-odd-forced", "admin-odd-forced@example.com", "OldPassw0rd!")
		rawKey := seedRecoveryKey(t, ctx, store)
		if err := store.SetAccountState(ctx, user.ID, rawState, time.Now()); err != nil {
			t.Fatalf("SetAccountState: %v", err)
		}

		summary, err := performRecoverAdminOpts(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false, 0, true)
		if err != nil {
			t.Fatalf("performRecoverAdminOpts with force: %v", err)
		}
		if summary.liftedState != rawState {
			t.Errorf("liftedState = %q, want %q", summary.liftedState, rawState)
		}
		done := "admin.recover_admin"
		events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &done, PageSize: 10})
		if err != nil || len(events) != 1 {
			t.Fatalf("want 1 %s event, got %d (err %v)", done, len(events), err)
		}
		if !strings.Contains(events[0].Description, "unrecognised account state "+quoted) {
			t.Errorf("audit event does not quote the replaced state: %q", events[0].Description)
		}
	})
}
