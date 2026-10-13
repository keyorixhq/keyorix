package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/recoverykey"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	storelib "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newRecoverAdminTestStore returns a *storelib.LocalStorage over a unique
// in-memory SQLite database, migrated for every table performRecoverAdmin's
// full reset touches (recover_admin_logic.go) plus role/group tables for
// the global-admin-role check (recovery_notify.go).
func newRecoverAdminTestStore(t *testing.T) *storelib.LocalStorage {
	store, _ := newRecoverAdminTestStoreWithDSN(t)
	return store
}

// newRecoverAdminTestStoreWithDSN is newRecoverAdminTestStore, also
// returning the shared-cache DSN so a test can open a SECOND connection to
// the same in-memory database (e.g. to corrupt a row directly, bypassing
// LocalStorage's own write paths, the same technique the audit chain's own
// tamper-detection tests use).
func newRecoverAdminTestStoreWithDSN(t *testing.T) (*storelib.LocalStorage, string) {
	t.Helper()
	// GetUserRoleIDsAt's not-found/error paths (and several other storage
	// methods this package's tests exercise) call i18n.T for a localized
	// message -- never initialized in this process outside loadConfig()
	// (server/admin/admin.go), which these in-package tests bypass entirely
	// by calling storage.Storage directly. InitializeForTesting is
	// sync.Once-guarded, so calling it once per test is a safe no-op after
	// the first.
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n.InitializeForTesting: %v", err)
	}
	// The DSN is handed back so one test can open a deliberate SECOND connection
	// to the same database; capture it from the dialector factory.
	var dsn string
	db := sqlitetest.OpenWithDialector(t, "recover_admin_", func(d string) gorm.Dialector {
		dsn = d
		return sqlite.Open(d)
	}, &gorm.Config{})
	if err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.GroupRole{}, &models.UserGroup{},
		&models.Project{}, &models.Environment{},
		&models.RecoveryKeyRecord{},
		&models.Session{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.WebAuthnCredential{},
		&models.AuditEvent{}, &models.AuditCheckpoint{},
		&models.Notification{},
		// core.ChangePassword (TestPerformRecoverAdmin_OTPActuallyLogsIn's forced
		// password change) reads/writes password history and lists PATs when
		// dropping the user's other sessions/credentials on a real change.
		&models.PasswordHistory{}, &models.PersonalAccessToken{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return storelib.NewLocalStorage(db), dsn
}

// seedAdminUser creates an active user holding a global-admin role (the
// structural BypassesPermissionChecks flag, ADR-084) with a real password
// hash, matching what core.CreateUser would produce (UsernameFolded/
// EmailFolded set) -- storage.CreateUser itself does not fold (see its own
// doc comment), so a test fixture that skips this would silently diverge
// from what every real caller of this table actually writes.
func seedAdminUser(t *testing.T, ctx context.Context, store storage.Storage, username, email, password string) *models.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	usernameFolded, err := identity.NewFoldedName(username)
	if err != nil {
		t.Fatalf("fold username: %v", err)
	}
	emailFolded, err := identity.NewFoldedName(email)
	if err != nil {
		t.Fatalf("fold email: %v", err)
	}
	user := &models.User{
		Username:       username,
		UsernameFolded: usernameFolded.Folded(),
		Email:          email,
		EmailFolded:    emailFolded.Folded(),
		PasswordHash:   string(hash),
		IsActive:       true,
		AccountState:   "active",
	}
	created, err := store.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	roleName, err := identity.NewFoldedName("global-admin-" + username)
	if err != nil {
		t.Fatalf("fold role name: %v", err)
	}
	role, err := store.CreateRole(ctx, roleName, "test admin role")
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := store.SetRoleBypassesPermissionChecks(ctx, role.ID, true); err != nil {
		t.Fatalf("set role bypasses permission checks: %v", err)
	}
	if err := store.AssignRole(ctx, created.ID, role.ID, storage.Scope{}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	return created
}

// seedRecoveryKey generates a fresh recovery key, stores its verifier as
// generation 1, and returns the raw key.
func seedRecoveryKey(t *testing.T, ctx context.Context, store storage.Storage) string {
	t.Helper()
	raw, err := recoverykey.Generate()
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	err = store.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{
		KeyHash:    recoverykey.Hash(raw),
		KeyVersion: 1,
		CreatedAt:  time.Now(),
	})
	if err != nil {
		t.Fatalf("seed recovery key record: %v", err)
	}
	return raw
}

func TestPerformRecoverAdmin_HappyPath(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin1", "admin1@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	// Seed state that a real locked-out admin might have: MFA enrolled, a
	// WebAuthn credential, an active session, and login-lockout counters.
	if err := store.SetUserMFAEnabled(ctx, user.ID, true); err != nil {
		t.Fatalf("enable MFA: %v", err)
	}
	if err := store.CreateMFARecoveryCodes(ctx, user.ID, []string{"hash1", "hash2"}); err != nil {
		t.Fatalf("create MFA recovery codes: %v", err)
	}
	if err := store.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: user.ID, CredentialID: []byte("cred-1"), Name: "Test Key", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create webauthn credential: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	if _, err := store.CreateSession(ctx, &models.Session{
		UserID: user.ID, SessionToken: "sesshash1", ExpiresAt: &exp, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	lockedUntil := time.Now().Add(10 * time.Minute)
	if err := store.UpdateLoginLockoutState(ctx, user.ID, 5, &lockedUntil, &lockedUntil, 2); err != nil {
		t.Fatalf("seed lockout state: %v", err)
	}

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}

	if summary.userID != user.ID || summary.username != user.Username {
		t.Errorf("summary identifies wrong user: %+v", summary)
	}
	if summary.webAuthnCredentialsCleared != 1 {
		t.Errorf("webAuthnCredentialsCleared = %d, want 1", summary.webAuthnCredentialsCleared)
	}
	if summary.sessionsRevoked != 1 {
		t.Errorf("sessionsRevoked = %d, want 1", summary.sessionsRevoked)
	}
	if summary.auditChainBroken {
		t.Errorf("auditChainBroken = true on a fresh chain, want false")
	}

	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser after recovery: %v", err)
	}
	if got.AccountState != "password_reset_required" {
		t.Errorf("AccountState = %q, want password_reset_required", got.AccountState)
	}
	if got.PasswordHash == "" {
		t.Errorf("PasswordHash is empty -- the recovered admin has no way to log in")
	}
	if summary.oneTimePassword == "" {
		t.Errorf("summary.oneTimePassword is empty -- nothing to print for the operator to log in with")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(summary.oneTimePassword)); err != nil {
		t.Errorf("stored PasswordHash does not match summary.oneTimePassword: %v", err)
	}
	if got.MFAEnabled {
		t.Errorf("MFAEnabled = true, want false (cleared)")
	}
	if got.LoginLockedUntil != nil || got.FailedLoginAttempts != 0 || got.LoginLockoutCount != 0 {
		t.Errorf("lockout state not cleared: %+v", got)
	}

	creds, err := store.ListWebAuthnCredentials(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 WebAuthn credentials after recovery, got %d", len(creds))
	}

	tokens, err := store.ListSessionTokenHashesForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListSessionTokenHashesForUser: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 sessions after recovery, got %d", len(tokens))
	}

	// Audit event written.
	action := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 admin.recover_admin audit event, got %d", len(events))
	}

	// Admin notification written (the recovered user themself, being the
	// only admin on this fixture).
	notifications, err := store.ListNotifications(ctx, user.ID, false, 10)
	if err != nil {
		t.Fatalf("ListNotifications: %v", err)
	}
	_ = notifications // notification fan-out is exercised by runRecoverAdmin, not performRecoverAdmin directly
}

// TestPerformRecoverAdmin_OTPActuallyLogsIn is the fix's own regression test:
// before it, recover-admin cleared the password hash to "" and
// VerifyPasswordCredentials's bcrypt compare against "" fails unconditionally
// for every password — the official emergency-recovery path ended with the
// admin still locked out, permanently. Drives the full documented sequence
// end to end through internal/core (the real login/change-password code, not
// a re-implementation of it): recover-admin -> log in with the printed OTP
// -> forced password change -> log in with the new password. Also confirms
// the OTP itself stops working once superseded, and that the account is no
// longer confined to password_reset_required afterward.
func TestPerformRecoverAdmin_OTPActuallyLogsIn(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin-otp", "admin-otp@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}
	if summary.oneTimePassword == "" {
		t.Fatalf("no one-time password printed")
	}

	c := core.NewKeyorixCore(store)

	// Step 1: log in with the printed OTP. This must succeed even though the
	// account is still password_reset_required — VerifyPasswordCredentials
	// itself does not refuse a restricted account (only the higher HTTP-layer
	// middleware confines its session to the password-change allowlist).
	loggedIn, err := c.VerifyPasswordCredentials(ctx, user.Username, summary.oneTimePassword)
	if err != nil {
		t.Fatalf("login with the printed one-time password failed: %v", err)
	}
	if loggedIn.ID != user.ID {
		t.Fatalf("VerifyPasswordCredentials returned the wrong user: got %d, want %d", loggedIn.ID, user.ID)
	}
	if loggedIn.AccountState != "password_reset_required" {
		t.Fatalf("AccountState = %q, want password_reset_required (still forced to change it)", loggedIn.AccountState)
	}

	// Step 2: forced password change, using the OTP as the "current" password
	// ChangePassword itself verifies.
	const newPassword = "Recovered-Op3rator-Passw0rd!-2026"
	if err := c.ChangePassword(ctx, user.ID, summary.oneTimePassword, newPassword, ""); err != nil {
		t.Fatalf("ChangePassword with the one-time password as current failed: %v", err)
	}

	// Step 3: log in with the NEW password.
	relogged, err := c.VerifyPasswordCredentials(ctx, user.Username, newPassword)
	if err != nil {
		t.Fatalf("login with the new password failed: %v", err)
	}
	if relogged.AccountState == "password_reset_required" {
		t.Errorf("AccountState still password_reset_required after a real password change")
	}

	// The superseded OTP must no longer work.
	if _, err := c.VerifyPasswordCredentials(ctx, user.Username, summary.oneTimePassword); err == nil {
		t.Errorf("the one-time password still logs in after it was superseded by a real password change")
	}
}

func TestPerformRecoverAdmin_WrongKeyRejected(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin2", "admin2@example.com", "OldPassw0rd!")
	_ = seedRecoveryKey(t, ctx, store)

	other, err := recoverykey.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, err = performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), other, false)
	if err == nil {
		t.Fatalf("expected performRecoverAdmin to fail with the wrong key")
	}

	// Confirm nothing was touched.
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.AccountState == "password_reset_required" {
		t.Errorf("account state was changed despite the wrong key being rejected")
	}
	if got.PasswordHash == "" {
		t.Errorf("password hash was cleared despite the wrong key being rejected")
	}
}

func TestPerformRecoverAdmin_NoKeyGeneratedYetRefuses(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin3", "admin3@example.com", "OldPassw0rd!")

	_, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), "ANYTHING", false)
	if err == nil {
		t.Fatalf("expected performRecoverAdmin to refuse when no recovery key has ever been generated")
	}
}

// TestPerformRecoverAdmin_KeylessModeSkipsKeyVerification exercises design
// §5's labs/demo escape hatch: with keyless=true, recovery succeeds on host
// access alone even when NO recovery key has ever been generated on this
// install, and the summary records that no key generation backs it.
func TestPerformRecoverAdmin_KeylessModeSkipsKeyVerification(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin6", "admin6@example.com", "OldPassw0rd!")

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), "", true)
	if err != nil {
		t.Fatalf("expected keyless recovery to succeed with no recovery key generated, got: %v", err)
	}
	if !summary.keyless {
		t.Errorf("expected summary.keyless = true")
	}
	if summary.recoveryKeyVersion != 0 {
		t.Errorf("recoveryKeyVersion = %d, want 0 (no key was checked)", summary.recoveryKeyVersion)
	}

	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.AccountState != "password_reset_required" {
		t.Errorf("AccountState = %q, want password_reset_required", got.AccountState)
	}

	// The audit event must say so explicitly — keyless recovery must never
	// look, on the record, like a genuine key-backed one.
	action := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(events) != 1 || !strings.Contains(events[0].Description, "KEYLESS MODE") {
		t.Fatalf("expected the audit event to explicitly say KEYLESS MODE, got: %+v", events)
	}
}

func TestPerformRecoverAdmin_NonAdminTargetRefused(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	rawKey := seedRecoveryKey(t, ctx, store)

	hash, err := bcrypt.GenerateFromPassword([]byte("Passw0rd!"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	usernameFolded, _ := identity.NewFoldedName("regular")
	emailFolded, _ := identity.NewFoldedName("regular@example.com")
	regular, err := store.CreateUser(ctx, &models.User{
		Username: "regular", UsernameFolded: usernameFolded.Folded(),
		Email: "regular@example.com", EmailFolded: emailFolded.Folded(),
		PasswordHash: string(hash), IsActive: true, AccountState: "active",
	})
	if err != nil {
		t.Fatalf("create regular user: %v", err)
	}

	_, err = performRecoverAdmin(ctx, store, fmt.Sprintf("%d", regular.ID), rawKey, false)
	if err == nil {
		t.Fatalf("expected performRecoverAdmin to refuse a non-admin target")
	}
}

func TestPerformRecoverAdmin_UnknownUserRefused(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	rawKey := seedRecoveryKey(t, ctx, store)

	if _, err := performRecoverAdmin(ctx, store, "999999", rawKey, false); err == nil {
		t.Errorf("expected refusal for an unknown numeric user id")
	}
	if _, err := performRecoverAdmin(ctx, store, "nobody@example.com", rawKey, false); err == nil {
		t.Errorf("expected refusal for an unknown email")
	}
}

// TestPerformRecoverAdmin_OldKeyRejectedAfterRotation exercises design §6's
// own adversarial-review item at the system level (recoverykey_test.go
// already covers it at the pure crypto-primitive level): a key that was
// valid before a rotation must be rejected immediately after, no grace
// window.
func TestPerformRecoverAdmin_OldKeyRejectedAfterRotation(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "admin4", "admin4@example.com", "OldPassw0rd!")
	oldKey := seedRecoveryKey(t, ctx, store)

	newKey, err := recoverykey.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	now := time.Now()
	if err := store.SetRecoveryKeyRecord(ctx, &models.RecoveryKeyRecord{
		KeyHash: recoverykey.Hash(newKey), KeyVersion: 2, CreatedAt: now, RotatedAt: &now,
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), oldKey, false); err == nil {
		t.Fatalf("expected the OLD (pre-rotation) key to be rejected")
	}

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), newKey, false)
	if err != nil {
		t.Fatalf("expected the NEW key to succeed: %v", err)
	}
	if summary.recoveryKeyVersion != 2 {
		t.Errorf("recoveryKeyVersion = %d, want 2", summary.recoveryKeyVersion)
	}
}

// TestPerformRecoverAdmin_BrokenAuditChainStillRecovers exercises design
// §4/§6: a broken audit chain does not block recovery (refusing would be
// the worse outcome), but the run must be recorded as having occurred while
// the chain was already compromised.
func TestPerformRecoverAdmin_BrokenAuditChainStillRecovers(t *testing.T) {
	ctx := context.Background()
	store, dsn := newRecoverAdminTestStoreWithDSN(t)
	user := seedAdminUser(t, ctx, store, "admin5", "admin5@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)

	// Write one legitimate chained event, then corrupt its entry_hash via a
	// SECOND connection to the same shared-cache in-memory database --
	// bypassing LocalStorage's own write path entirely, the same tamper
	// simulation technique local_audit_chain_test.go's own VerifyAuditChain
	// tests use.
	ok := true
	if err := store.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "test.seed", Description: "seed", Success: &ok, ActorType: "test", EventTime: time.Now(),
	}); err != nil {
		t.Fatalf("seed audit event: %v", err)
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
	if err := rawDB.Exec("UPDATE audit_events SET entry_hash = 'corrupted' WHERE event_type = 'test.seed'").Error; err != nil {
		t.Fatalf("corrupt audit row: %v", err)
	}

	summary, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false)
	if err != nil {
		t.Fatalf("performRecoverAdmin must still succeed on a broken chain (refusing would be worse), got: %v", err)
	}
	if !summary.auditChainBroken {
		t.Errorf("expected summary.auditChainBroken = true after corrupting a row, got false")
	}
	if summary.auditChainFirstBrokenID == 0 {
		t.Errorf("expected a non-zero auditChainFirstBrokenID")
	}

	// The recovery's OWN event must still have been written despite the
	// broken chain -- recording alongside it, not refusing because of it.
	action := "admin.recover_admin"
	events, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, PageSize: 10})
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected the recovery event to still be written on a broken chain, got %d", len(events))
	}
}
