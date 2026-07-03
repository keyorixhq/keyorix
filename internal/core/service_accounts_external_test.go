package core_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Service-account client secrets and tokens must be stored as a SHA-256 hash, never
// as recoverable plaintext — a DB read (backup, replica, injection, insider) must not
// yield a usable credential. The plaintext is returned to the caller exactly once.
func TestServiceAccount_CredentialsHashedAtRest(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.APIClient{}, &models.APIToken{}, &models.AuditEvent{}))
	ctx := context.Background()

	acct, err := h.CoreService.CreateServiceAccount(ctx, 1, &core.CreateServiceAccountRequest{Name: "ci-bot"})
	require.NoError(t, err)
	require.NotEmpty(t, acct.PlainClientSecret, "the plaintext secret is returned once")

	var storedClient models.APIClient
	require.NoError(t, h.DB.First(&storedClient, "client_id = ?", acct.ClientID).Error)
	assert.NotEqual(t, acct.PlainClientSecret, storedClient.ClientSecret, "plaintext secret must not be stored")
	assert.Equal(t, sha256Hex(acct.PlainClientSecret), storedClient.ClientSecret, "the stored secret is its SHA-256 hash")
	assert.Empty(t, storedClient.EncryptedClientSecret, "no half-encrypted column left behind")

	tok, err := h.CoreService.CreateServiceToken(ctx, 1, acct.ClientID, &core.CreateServiceTokenRequest{Scope: "read"})
	require.NoError(t, err)
	require.NotEmpty(t, tok.PlainToken)

	var storedTok models.APIToken
	require.NoError(t, h.DB.First(&storedTok, "id = ?", tok.APIToken.ID).Error)
	assert.NotEqual(t, tok.PlainToken, storedTok.Token, "plaintext token must not be stored")
	assert.Equal(t, sha256Hex(tok.PlainToken), storedTok.Token, "the stored token is its SHA-256 hash")
}

// Every service-account/token lifecycle transition (create/update/revoke,
// token create/revoke) must produce an audit record — same silent-audit-gap family as
// #233/#234 (#279).
func TestServiceAccount_LifecycleEventsAudited(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.APIClient{}, &models.APIToken{}, &models.AuditEvent{}))
	ctx := context.Background()
	const actorID = uint(7)

	acct, err := h.CoreService.CreateServiceAccount(ctx, actorID, &core.CreateServiceAccountRequest{Name: "ci-bot"})
	require.NoError(t, err)

	_, err = h.CoreService.UpdateServiceAccount(ctx, actorID, acct.ClientID, &core.UpdateServiceAccountRequest{
		Name:     "ci-bot-renamed",
		IsActive: true,
	})
	require.NoError(t, err)

	tok, err := h.CoreService.CreateServiceToken(ctx, actorID, acct.ClientID, &core.CreateServiceTokenRequest{Scope: "read"})
	require.NoError(t, err)

	require.NoError(t, h.CoreService.RevokeServiceToken(ctx, actorID, tok.APIToken.ID))
	require.NoError(t, h.CoreService.RevokeServiceAccount(ctx, actorID, acct.ClientID))

	var events []models.AuditEvent
	require.NoError(t, h.DB.Order("id asc").Find(&events).Error)

	byType := map[string]models.AuditEvent{}
	for _, e := range events {
		byType[e.EventType] = e
	}

	for _, wantType := range []string{
		"service_account.created",
		"service_account.updated",
		"service_account.revoked",
		"service_token.created",
		"service_token.revoked",
	} {
		e, ok := byType[wantType]
		require.True(t, ok, "expected an audit event of type %s", wantType)
		require.NotNil(t, e.UserID, "expected an actor recorded on the %s event", wantType)
		assert.Equal(t, actorID, *e.UserID)
	}
}

// A change made without an authenticated principal (actorID 0, e.g. a local CLI
// invocation) records no actor on the audit row — same convention as the RBAC audit
// trail (see TestRBACAuditTrail_SystemActor).
func TestServiceAccount_LifecycleAuditSystemActor(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.APIClient{}, &models.APIToken{}, &models.AuditEvent{}))
	ctx := context.Background()

	_, err := h.CoreService.CreateServiceAccount(ctx, 0, &core.CreateServiceAccountRequest{Name: "cli-bot"})
	require.NoError(t, err)

	var event models.AuditEvent
	require.NoError(t, h.DB.Where("event_type = ?", "service_account.created").First(&event).Error)
	assert.Nil(t, event.UserID, "system/CLI actor should be unset")
}
