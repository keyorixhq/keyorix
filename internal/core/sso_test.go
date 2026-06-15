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

	sub, email, err := c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", base()))
	require.NoError(t, err)
	assert.Equal(t, "okta|123", sub)
	assert.Equal(t, "ada@x.io", email)

	// Wrong audience → rejected.
	bad := base()
	bad["aud"] = "someone-else"
	_, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", bad))
	require.Error(t, err)

	// Nonce mismatch → rejected (replay / mix-up protection).
	_, _, err = c.verifyIDToken(ctx, p, "WRONG", signToken(t, key, "kid-1", base()))
	require.Error(t, err)

	// Expired → rejected.
	exp := base()
	exp["exp"] = time.Now().Add(-time.Hour).Unix()
	_, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", exp))
	require.Error(t, err)

	// Wrong issuer → rejected (keyfn refuses it).
	iss := base()
	iss["iss"] = "https://evil.test"
	_, _, err = c.verifyIDToken(ctx, p, "N1", signToken(t, key, "kid-1", iss))
	require.Error(t, err)
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

	t.Run("no match errors", func(t *testing.T) {
		c, store, _, _ := ssoTestCore(t)
		store.On("GetUserByExternalID", mock.Anything, "okta|123").Return((*models.User)(nil), notFound())
		store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return((*models.User)(nil), notFound())
		_, err := c.resolveSSOUser(context.Background(), "okta|123", "ada@x.io")
		require.Error(t, err)
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
