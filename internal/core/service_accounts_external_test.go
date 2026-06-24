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
	require.NoError(t, h.DB.AutoMigrate(&models.APIClient{}, &models.APIToken{}))
	ctx := context.Background()

	acct, err := h.CoreService.CreateServiceAccount(ctx, &core.CreateServiceAccountRequest{Name: "ci-bot"})
	require.NoError(t, err)
	require.NotEmpty(t, acct.PlainClientSecret, "the plaintext secret is returned once")

	var storedClient models.APIClient
	require.NoError(t, h.DB.First(&storedClient, "client_id = ?", acct.ClientID).Error)
	assert.NotEqual(t, acct.PlainClientSecret, storedClient.ClientSecret, "plaintext secret must not be stored")
	assert.Equal(t, sha256Hex(acct.PlainClientSecret), storedClient.ClientSecret, "the stored secret is its SHA-256 hash")
	assert.Empty(t, storedClient.EncryptedClientSecret, "no half-encrypted column left behind")

	tok, err := h.CoreService.CreateServiceToken(ctx, acct.ClientID, &core.CreateServiceTokenRequest{Scope: "read"})
	require.NoError(t, err)
	require.NotEmpty(t, tok.PlainToken)

	var storedTok models.APIToken
	require.NoError(t, h.DB.First(&storedTok, "id = ?", tok.APIToken.ID).Error)
	assert.NotEqual(t, tok.PlainToken, storedTok.Token, "plaintext token must not be stored")
	assert.Equal(t, sha256Hex(tok.PlainToken), storedTok.Token, "the stored token is its SHA-256 hash")
}
