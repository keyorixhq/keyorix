package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A suspended or deprovisioned account is blocked on purpose (an admin's
// security action, an IdP deactivation). recover-admin must not lift that
// silently: by default it refuses, changes nothing and records the refusal.
func TestPerformRecoverAdmin_RefusesBlockedStateByDefault(t *testing.T) {
	for _, state := range []string{core.AccountSuspended, core.AccountDeprovisioned} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			store := newRecoverAdminTestStore(t)
			user := seedAdminUser(t, ctx, store, "admin-blocked", "admin-blocked@example.com", "OldPassw0rd!")
			rawKey := seedRecoveryKey(t, ctx, store)
			if err := store.SetAccountState(ctx, user.ID, state, time.Now()); err != nil {
				t.Fatalf("SetAccountState: %v", err)
			}
			before, err := store.GetUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}

			_, err = performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
			if err == nil {
				t.Fatalf("recover-admin lifted a %s account without --force-unsuspend", state)
			}
			if !strings.Contains(err.Error(), "--force-unsuspend") || !strings.Contains(err.Error(), state) {
				t.Errorf("error does not name the state and the flag: %v", err)
			}

			after, err := store.GetUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUser after: %v", err)
			}
			if after.AccountState != state {
				t.Errorf("AccountState = %q after a refused run, want %q", after.AccountState, state)
			}
			if after.PasswordHash != before.PasswordHash {
				t.Errorf("password hash changed by a refused run")
			}

			failed := "admin.recover_admin_failed"
			events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &failed, PageSize: 10})
			if err != nil || len(events) != 1 {
				t.Fatalf("want 1 %s event, got %d (err %v)", failed, len(events), err)
			}
			if !strings.Contains(events[0].Description, "--force-unsuspend was not given") {
				t.Errorf("refusal event does not say why: %q", events[0].Description)
			}
			done := "admin.recover_admin"
			if recovered, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &done, PageSize: 10}); err != nil || len(recovered) != 0 {
				t.Errorf("a refused run was recorded as a recovery: %d event(s), err %v", len(recovered), err)
			}
		})
	}
}

// With --force-unsuspend the recovery goes through and the audit event names
// the state that was lifted.
func TestPerformRecoverAdmin_ForceUnsuspendLiftsAndRecords(t *testing.T) {
	for _, state := range []string{core.AccountSuspended, core.AccountDeprovisioned} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			store := newRecoverAdminTestStore(t)
			user := seedAdminUser(t, ctx, store, "admin-forced", "admin-forced@example.com", "OldPassw0rd!")
			rawKey := seedRecoveryKey(t, ctx, store)
			if err := store.SetAccountState(ctx, user.ID, state, time.Now()); err != nil {
				t.Fatalf("SetAccountState: %v", err)
			}

			summary, err := performRecoverAdminOpts(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false, 0, true)
			if err != nil {
				t.Fatalf("performRecoverAdminOpts with force: %v", err)
			}
			if summary.liftedState != state {
				t.Errorf("liftedState = %q, want %q", summary.liftedState, state)
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
			if !strings.Contains(events[0].Description, state) || !strings.Contains(events[0].Description, "--force-unsuspend") {
				t.Errorf("audit event does not record the lifted state: %q", events[0].Description)
			}
		})
	}
}

// An account that is not blocked is recovered without the flag, and the audit
// event carries no lifted-state note.
func TestPerformRecoverAdmin_ActiveAccountNeedsNoFlag(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-plain", "admin-plain@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}
	if summary.liftedState != "" {
		t.Errorf("liftedState = %q for an active account", summary.liftedState)
	}
}

// seedSecondFactors enrolls TOTP and one WebAuthn credential on userID, the
// second factors a refused recover-admin run must leave in place.
func seedSecondFactors(t *testing.T, ctx context.Context, store storage.Storage, userID uint) {
	t.Helper()
	if err := store.SetUserMFAEnabled(ctx, userID, true); err != nil {
		t.Fatalf("enable MFA: %v", err)
	}
	if err := store.SetUserWebAuthnEnabled(ctx, userID, true); err != nil {
		t.Fatalf("enable WebAuthn: %v", err)
	}
	if err := store.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: userID, CredentialID: []byte("blocked-cred"), Name: "Key", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create webauthn credential: %v", err)
	}
}

// assertSecondFactorsIntact fails when a refused run touched the second factors.
func assertSecondFactorsIntact(t *testing.T, ctx context.Context, store storage.Storage, userID uint, state string) {
	t.Helper()
	got, err := store.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !got.MFAEnabled || !got.WebAuthnEnabled {
		t.Errorf("refused run cleared a second-factor flag: MFAEnabled=%v WebAuthnEnabled=%v", got.MFAEnabled, got.WebAuthnEnabled)
	}
	if got.AccountState != state {
		t.Errorf("AccountState = %q after a refused run, want %q", got.AccountState, state)
	}
	creds, err := store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentials: %v", err)
	}
	if len(creds) != 1 {
		t.Errorf("refused run deleted WebAuthn credentials: %d left, want 1", len(creds))
	}
}

// The blocked-state refusal returns before the reset transaction: MFA and
// WebAuthn survive it (guard: TestEverySecondFactorClearerCallerIsAllowlisted
// allows performRecoverAdminOpts only because its clears follow every check).
func TestPerformRecoverAdmin_BlockedRefusalKeepsSecondFactors(t *testing.T) {
	for _, state := range []string{core.AccountSuspended, core.AccountDeprovisioned} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			store := newRecoverAdminTestStore(t)
			user := seedAdminUser(t, ctx, store, "admin-2fa", "admin-2fa@example.com", "OldPassw0rd!")
			rawKey := seedRecoveryKey(t, ctx, store)
			seedSecondFactors(t, ctx, store, user.ID)
			if err := store.SetAccountState(ctx, user.ID, state, time.Now()); err != nil {
				t.Fatalf("SetAccountState: %v", err)
			}

			if _, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false); err == nil {
				t.Fatalf("recover-admin lifted a %s account without --force-unsuspend", state)
			}
			assertSecondFactorsIntact(t, ctx, store, user.ID, state)
		})
	}
}

// --force-unsuspend lifts only the state block, never the recovery-key check:
// with a wrong key the run is refused and nothing changes.
func TestPerformRecoverAdmin_ForceUnsuspendStillNeedsRecoveryKey(t *testing.T) {
	for _, state := range []string{core.AccountSuspended, core.AccountDeprovisioned} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			store := newRecoverAdminTestStore(t)
			user := seedAdminUser(t, ctx, store, "admin-nokey", "admin-nokey@example.com", "OldPassw0rd!")
			_ = seedRecoveryKey(t, ctx, store)
			seedSecondFactors(t, ctx, store, user.ID)
			if err := store.SetAccountState(ctx, user.ID, state, time.Now()); err != nil {
				t.Fatalf("SetAccountState: %v", err)
			}

			_, err := performRecoverAdminOpts(ctx, store, fmt.Sprintf("%d", user.ID), "not-the-key", false, 0, true)
			if err == nil || !strings.Contains(err.Error(), "recovery key does not match") {
				t.Fatalf("--force-unsuspend with a wrong key: err = %v, want a key mismatch", err)
			}
			assertSecondFactorsIntact(t, ctx, store, user.ID, state)
			done := "admin.recover_admin"
			if recovered, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &done, PageSize: 10}); err != nil || len(recovered) != 0 {
				t.Errorf("a refused run was recorded as a recovery: %d event(s), err %v", len(recovered), err)
			}
		})
	}
}
