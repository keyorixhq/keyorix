package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// recover-admin removes every WebAuthn credential, so it must clear the
// WebAuthnEnabled flag too: login demands a passkey assertion from a
// WebAuthnEnabled account, and with zero credentials left that assertion can
// never be produced (internal/core/webauthn.go calls this state a permanent
// lockout). The one recovery path for a locked-out passkey admin would end in
// the admin still locked out.
func TestPerformRecoverAdmin_ClearsWebAuthnFlag(t *testing.T) {
	ctx := context.Background()
	store := newRecoverAdminTestStore(t)
	user := seedAdminUser(t, ctx, store, "passkey-admin", "passkey-admin@example.com", "OldPassw0rd!")
	rawKey := seedRecoveryKey(t, ctx, store)
	if err := store.CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: user.ID, CredentialID: []byte("cred-passkey"), Name: "Key", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create webauthn credential: %v", err)
	}
	if err := store.SetUserWebAuthnEnabled(ctx, user.ID, true); err != nil {
		t.Fatalf("enable webauthn: %v", err)
	}

	if _, err := performRecoverAdmin(ctx, store, fmt.Sprintf("%d", user.ID), rawKey, false); err != nil {
		t.Fatalf("performRecoverAdmin: %v", err)
	}
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.WebAuthnEnabled {
		t.Fatal("WebAuthnEnabled is still true with zero credentials: the recovered admin is asked for a passkey it no longer has")
	}
}
