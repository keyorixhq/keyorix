package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	storelib "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func newResetMFATestStore(t *testing.T) *storelib.LocalStorage {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	db := sqlitetest.OpenWithDialector(t, "reset_mfa_", sqlite.Open, &gorm.Config{})
	if err := db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Group{}, &models.GroupRole{}, &models.UserGroup{},
		&models.Project{}, &models.Environment{},
		&models.RecoveryKeyRecord{}, &models.Session{},
		&models.MFASecret{}, &models.MFARecoveryCode{}, &models.MFAStepUpGrant{},
		&models.WebAuthnCredential{}, &models.PersonalAccessToken{},
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.Notification{},
		&models.MachineIdentity{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return storelib.NewLocalStorage(db)
}

// seedEnrolledUser creates an active, local, non-admin user with every kind of
// credential a reset must remove: an activated TOTP secret, two recovery codes, a
// WebAuthn credential, a session and a PAT.
func seedEnrolledUser(t *testing.T, ctx context.Context, store storage.Storage, username string) *models.User {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("old-password-1!"), bcrypt.MinCost)
	uf, _ := identity.NewFoldedName(username)
	ef, _ := identity.NewFoldedName(username + "@example.com")
	u, err := store.CreateUser(ctx, &models.User{
		Username: username, UsernameFolded: uf.Folded(),
		Email: username + "@example.com", EmailFolded: ef.Folded(),
		PasswordHash: string(hash), IsActive: true, AccountState: "active",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	must("mfa secret", store.UpsertMFASecret(ctx, &models.MFASecret{UserID: u.ID, SecretEnc: []byte("enc"), Activated: true}))
	must("mfa flag", store.SetUserMFAEnabled(ctx, u.ID, true))
	must("recovery codes", store.CreateMFARecoveryCodes(ctx, u.ID, []string{"h1", "h2"}))
	must("webauthn", store.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{UserID: u.ID, CredentialID: []byte(username), Name: "key"}))
	must("webauthn flag", store.SetUserWebAuthnEnabled(ctx, u.ID, true))
	exp := time.Now().Add(time.Hour)
	_, err = store.CreateSession(ctx, &models.Session{UserID: u.ID, SessionToken: "sess-" + username, CreatedAt: time.Now(), ExpiresAt: &exp})
	must("session", err)
	_, err = store.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{UserID: u.ID, Name: "ci", TokenHash: "pat-" + username})
	must("pat", err)
	got, err := store.GetUser(ctx, u.ID)
	must("reread", err)
	return got
}

// assertCredentialsIntact fails if any credential of u was touched.
func assertCredentialsIntact(t *testing.T, ctx context.Context, store storage.Storage, uid uint) {
	t.Helper()
	u, _ := store.GetUser(ctx, uid)
	if !u.MFAEnabled || !u.WebAuthnEnabled || u.MFAEnrolmentRequired || u.AccountState != "active" {
		t.Fatalf("account changed: mfa=%v webauthn=%v enrolment_required=%v state=%q", u.MFAEnabled, u.WebAuthnEnabled, u.MFAEnrolmentRequired, u.AccountState)
	}
	if s, _ := store.GetMFASecret(ctx, uid); s == nil {
		t.Fatal("TOTP secret was removed")
	}
	if n, _ := store.CountUnusedMFARecoveryCodes(ctx, uid); n != 2 {
		t.Fatalf("recovery codes = %d, want 2", n)
	}
	if hashes, _ := store.ListSessionTokenHashesForUser(ctx, uid); len(hashes) != 1 {
		t.Fatalf("sessions = %d, want 1", len(hashes))
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("old-password-1!")) != nil {
		t.Fatal("password was replaced")
	}
}

func auditEventsOfType(t *testing.T, ctx context.Context, store storage.Storage, eventType string) []*models.AuditEvent {
	t.Helper()
	evs, _, err := store.GetAuditLogs(ctx, &storage.AuditFilter{Action: &eventType, PageSize: 50})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return evs
}

func TestPerformResetMFA_FullCredentialReset(t *testing.T) {
	ctx := context.Background()
	store := newResetMFATestStore(t)
	key := seedRecoveryKey(t, ctx, store)
	u := seedEnrolledUser(t, ctx, store, "alice")

	s, err := performResetMFA(ctx, store, "alice", key, false, time.Hour)
	if err != nil {
		t.Fatalf("reset-mfa: %v", err)
	}
	got, _ := store.GetUser(ctx, u.ID)
	if got.MFAEnabled || got.WebAuthnEnabled {
		t.Fatalf("factor flags still set: mfa=%v webauthn=%v", got.MFAEnabled, got.WebAuthnEnabled)
	}
	if !got.MFAEnrolmentRequired || !core.MFAEnrolmentOwed(got) {
		t.Fatal("mfa_enrolment_required not set")
	}
	if got.AccountState != core.AccountPasswordResetRequired || got.OneTimePasswordExpiresAt == nil {
		t.Fatalf("state=%q otp-expiry=%v, want password_reset_required with an expiry", got.AccountState, got.OneTimePasswordExpiresAt)
	}
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(s.oneTimePassword)) != nil {
		t.Fatal("the printed one-time password is not the account's password")
	}
	if sec, _ := store.GetMFASecret(ctx, u.ID); sec != nil {
		t.Fatal("TOTP secret survived")
	}
	if n, _ := store.CountUnusedMFARecoveryCodes(ctx, u.ID); n != 0 {
		t.Fatalf("%d recovery codes survived", n)
	}
	if creds, _ := store.ListWebAuthnCredentials(ctx, u.ID); len(creds) != 0 {
		t.Fatalf("%d WebAuthn credentials survived", len(creds))
	}
	if hashes, _ := store.ListSessionTokenHashesForUser(ctx, u.ID); len(hashes) != 0 {
		t.Fatalf("%d sessions survived", len(hashes))
	}
	pats, _ := store.ListPersonalAccessTokensByUser(ctx, u.ID)
	for _, p := range pats {
		if !p.Revoked {
			t.Fatalf("PAT %d survived", p.ID)
		}
	}
	if s.effect.SessionsRevoked != 1 || s.effect.PATsRevoked != 1 || s.effect.WebAuthnCredentialsCleared != 1 || s.effect.RecoveryCodesCleared != 2 || !s.effect.TOTPCleared {
		t.Fatalf("effect counts = %+v", s.effect)
	}
	evs := auditEventsOfType(t, ctx, store, eventAdminResetMFA)
	if len(evs) != 1 || evs[0].UserID == nil || *evs[0].UserID != u.ID {
		t.Fatalf("want one %s event for the target, got %d", eventAdminResetMFA, len(evs))
	}
	if strings.Contains(evs[0].Description, s.oneTimePassword) {
		t.Fatal("the audit event contains the one-time password")
	}
}

func TestPerformResetMFA_Refusals_ChangeNothing(t *testing.T) {
	ctx := context.Background()
	store := newResetMFATestStore(t)
	key := seedRecoveryKey(t, ctx, store)
	u := seedEnrolledUser(t, ctx, store, "bob")
	seedAdminUser(t, ctx, store, "root", "root@example.com", "Adm1n-password!")
	if _, err := store.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: 1, Name: "ci-runner", State: "active"}); err != nil {
		t.Fatalf("machine identity: %v", err)
	}

	cases := []struct {
		name, ref, key string
		want           error
	}{
		{"global admin", "root", key, core.ErrMFAResetGlobalAdmin},
		{"machine identity", "ci-runner", key, core.ErrMFAResetMachineIdentity},
		{"unknown user", "nobody", key, core.ErrMFAResetTargetNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := performResetMFA(ctx, store, tc.ref, tc.key, false, time.Hour); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("wrong recovery key is audited and changes nothing", func(t *testing.T) {
		if _, err := performResetMFA(ctx, store, "bob", "AAAA-BBBB-CCCC-DDDD", false, time.Hour); err == nil {
			t.Fatal("a wrong recovery key was accepted")
		}
		if n := len(auditEventsOfType(t, ctx, store, eventAdminResetMFAFailed)); n != 1 {
			t.Fatalf("%s events = %d, want 1", eventAdminResetMFAFailed, n)
		}
		assertCredentialsIntact(t, ctx, store, u.ID)
	})

	t.Run("sso account", func(t *testing.T) {
		sso := seedEnrolledUser(t, ctx, store, "carol")
		if claimed, err := store.ClaimUserExternalIDIfUnset(ctx, sso.ID, "idp-123", time.Now()); err != nil || !claimed {
			t.Fatalf("external id: claimed=%v err=%v", claimed, err)
		}
		if _, err := performResetMFA(ctx, store, "carol", key, false, time.Hour); !errors.Is(err, core.ErrMFAResetExternalIdentity) {
			t.Fatalf("err = %v, want the SSO refusal", err)
		}
	})

	t.Run("suspended account", func(t *testing.T) {
		sus := seedEnrolledUser(t, ctx, store, "dave")
		if err := store.SetAccountState(ctx, sus.ID, "suspended", time.Now()); err != nil {
			t.Fatalf("suspend: %v", err)
		}
		if _, err := performResetMFA(ctx, store, "dave", key, false, time.Hour); !errors.Is(err, core.ErrMFAResetAccountBlocked) {
			t.Fatalf("err = %v, want the blocked-account refusal", err)
		}
	})
	assertCredentialsIntact(t, ctx, store, u.ID)
}

// The reset and its audit row are one transaction: when the row cannot be
// written, the account keeps every factor, session and its password.
func TestPerformResetMFA_AuditOutage_LeavesMFAIntact(t *testing.T) {
	ctx := context.Background()
	real := newResetMFATestStore(t)
	key := seedRecoveryKey(t, ctx, real)
	u := seedEnrolledUser(t, ctx, real, "erin")

	faulty := faultstorage.NewFaultyStorage(real, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("audit log refused the row"),
	})
	if _, err := performResetMFA(ctx, faulty, "erin", key, false, time.Hour); err == nil {
		t.Fatal("reset-mfa succeeded although its audit row could not be written")
	}
	if !faulty.Fired() {
		t.Fatal("the audit fault never fired: the test did not exercise the outage")
	}
	assertCredentialsIntact(t, ctx, real, u.ID)
	if n := len(auditEventsOfType(t, ctx, real, eventAdminResetMFA)); n != 0 {
		t.Fatalf("%d %s events written", n, eventAdminResetMFA)
	}
}
