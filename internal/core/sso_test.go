package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func ssoTestCore(t *testing.T) (*KeyorixCore, *MockStorage, *rsa.PrivateKey, *SSOProvider) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := new(MockStorage)
	p := &SSOProvider{
		Name: "okta", Issuer: "https://idp.test", ClientID: "client-1",
		OAuth: &oauth2.Config{
			ClientID:    "client-1",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize", TokenURL: "https://idp.test/token"},
			RedirectURL: "https://keyorix.test/auth/sso/okta/callback",
			Scopes:      []string{"openid", "email"},
		},
		CompleteURL: "https://keyorix.test/auth/sso/complete",
	}
	c := &KeyorixCore{
		storage:      store,
		now:          time.Now,
		ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
		ssoProviders: map[string]*SSOProvider{"okta": p},
	}
	return c, store, key, p
}

func TestVerifyIDToken(t *testing.T) {
	c, _, key, p := ssoTestCore(t)
	ctx := context.Background()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": "client-1", "sub": "okta|123",
			"email": "ada@x.io", "nonce": "N1", "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	b := base()
	b["name"] = "Ada Lovelace"
	sub, email, name, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", b))
	require.NoError(t, err)
	assert.Equal(t, "okta|123", sub)
	assert.Equal(t, "ada@x.io", email)
	assert.Equal(t, "Ada Lovelace", name)

	// Wrong audience → rejected.
	bad := base()
	bad["aud"] = "someone-else"
	_, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", bad))
	require.Error(t, err)

	// Nonce mismatch → rejected (replay / mix-up protection).
	_, _, _, err = c.verifyIDToken(ctx, p, "WRONG", signToken(t, key, "kid-1", base()))
	require.Error(t, err)

	// Expired → rejected.
	exp := base()
	exp["exp"] = time.Now().Add(-time.Hour).Unix()
	_, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", exp))
	require.Error(t, err)

	// Wrong issuer → rejected (keyfn refuses it).
	iss := base()
	iss["iss"] = "https://evil.test"
	_, _, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", iss))
	require.Error(t, err)
}

func TestVerifyIDToken_EmailVerified(t *testing.T) {
	c, _, key, p := ssoTestCore(t)
	ctx := context.Background()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": "client-1", "sub": "okta|123",
			"email": "ada@x.io", "nonce": "N1", "exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	// email_verified absent → email is trusted (OIDC-optional; Entra omits it).
	_, email, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", base()))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)

	// email_verified: true → email trusted.
	ok := base()
	ok["email_verified"] = true
	_, email, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", ok))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)

	// email_verified: false → email DROPPED (untrusted), but the token still verifies
	// and the subject is unaffected.
	no := base()
	no["email_verified"] = false
	sub, email, _, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", no))
	require.NoError(t, err)
	assert.Equal(t, "okta|123", sub)
	assert.Empty(t, email)

	// email_verified sent as the string "false" → also dropped (no parse failure).
	noStr := base()
	noStr["email_verified"] = "false"
	_, email, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", noStr))
	require.NoError(t, err)
	assert.Empty(t, email)

	// email_verified sent as the string "true" → trusted.
	okStr := base()
	okStr["email_verified"] = "true"
	_, email, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", okStr))
	require.NoError(t, err)
	assert.Equal(t, "ada@x.io", email)
}

func TestResolveSSOUser(t *testing.T) {
	notFound := func() error { return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil)) }

	t.Run("externalId match wins", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return(&models.User{ID: 7}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta|123", "ada@x.io")
		require.NoError(t, err)
		assert.Equal(t, uint(7), u.ID)
		store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything)
	})

	t.Run("falls back to email", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return(&models.User{ID: 9}, nil)
		u, err := c.resolveSSOUser(context.Background(), "okta|123", "ada@x.io")
		require.NoError(t, err)
		assert.Equal(t, uint(9), u.ID)
	})

	t.Run("no match returns nil (caller decides)", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		u, err := c.resolveSSOUser(context.Background(), "okta|123", "ada@x.io")
		require.NoError(t, err)
		assert.Nil(t, u)
	})
}

func TestProvisionSSOUser(t *testing.T) {
	notFound := func() error { return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil)) }

	t.Run("JIT-creates an active passwordless user with the default role", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		// No existing match (FindSCIMUser re-check), unique username derivation.
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		var created *models.User
		store.On("CreateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			created = u
			return true
		})).Return(&models.User{ID: 42}, nil)
		store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 3}, nil)
		store.On("AssignRole", mock.Anything, uint(42), uint(3), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		u, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", "Ada Lovelace")
		require.NoError(t, err)
		assert.Equal(t, uint(42), u.ID)
		// Active (not pending_first_login — an SSO user must not be trapped in a
		// restricted password-change-only session), externalId pinned, real display name.
		assert.Equal(t, AccountActive, created.AccountState)
		assert.True(t, created.IsActive)
		assert.Equal(t, "okta|123", created.ExternalID)
		assert.Equal(t, "ada@x.io", created.Email)
		assert.Equal(t, "Ada Lovelace", created.DisplayName)
		assert.NotEmpty(t, created.PasswordHash) // unusable random hash, not blank
	})

	t.Run("refuses when the IdP returned no email", func(t *testing.T) {
		c, _, _, p := ssoTestCore(t)
		_, err := c.provisionSSOUser(context.Background(), p, "okta|123", "", "Ada")
		require.Error(t, err)
	})

	t.Run("reuses an existing user instead of duplicating", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return(&models.User{ID: 5}, nil)
		u, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", "Ada")
		require.NoError(t, err)
		assert.Equal(t, uint(5), u.ID)
		store.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
	})

	t.Run("honours a configured default_role", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		p.DefaultRole = "project_admin"
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		store.On("CreateUser", mock.Anything, mock.Anything).Return(&models.User{ID: 7}, nil)
		store.On("GetRoleByName", mock.Anything, "project_admin").Return(&models.Role{ID: 9}, nil)
		store.On("AssignRole", mock.Anything, uint(7), uint(9), mock.Anything).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		_, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", "Ada")
		require.NoError(t, err)
		store.AssertCalled(t, "GetRoleByName", mock.Anything, "project_admin")
	})

	t.Run("an unknown default_role grants nothing but still provisions", func(t *testing.T) {
		c, store, _, p := ssoTestCore(t)
		p.DefaultRole = "does_not_exist"
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		store.On("GetUserByUsername", mock.Anything, "ada").Return((*models.User)(nil), notFound())
		store.On("CreateUser", mock.Anything, mock.Anything).Return(&models.User{ID: 8}, nil)
		store.On("GetRoleByName", mock.Anything, "does_not_exist").Return((*models.Role)(nil), notFound())
		store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

		u, err := c.provisionSSOUser(context.Background(), p, "okta|123", "ada@x.io", "Ada")
		require.NoError(t, err)
		assert.Equal(t, uint(8), u.ID)
		store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestBeginSSO_BuildsAuthURLWithStateAndNonce(t *testing.T) {
	c, store, _, _ := ssoTestCore(t)
	var captured *models.SSOLoginState
	store.On("CreateSSOLoginState", mock.Anything, mock.MatchedBy(func(s *models.SSOLoginState) bool {
		captured = s
		return s.Provider == "okta" && s.State != "" && s.Nonce != ""
	})).Return(nil)

	raw, err := c.BeginSSO(context.Background(), "okta", "/secrets")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "idp.test", u.Host)
	q := u.Query()
	assert.Equal(t, captured.State, q.Get("state"))
	assert.Equal(t, captured.Nonce, q.Get("nonce"))
	assert.Equal(t, "client-1", q.Get("client_id"))
	assert.Equal(t, "/secrets", captured.ReturnTo)
}

func TestBeginSSO_UnknownProvider(t *testing.T) {
	c, _, _, _ := ssoTestCore(t)
	_, err := c.BeginSSO(context.Background(), "nope", "")
	require.Error(t, err)
}

func TestSanitizeReturnTo(t *testing.T) {
	assert.Equal(t, "/secrets", sanitizeReturnTo("/secrets"))
	assert.Equal(t, "", sanitizeReturnTo("//evil.com"))
	assert.Equal(t, "", sanitizeReturnTo("https://evil.com"))
	assert.Equal(t, "", sanitizeReturnTo("evil"))
}
