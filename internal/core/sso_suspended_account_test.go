// sso_suspended_account_test.go covers CompleteSSO's account-suspended/
// deactivated rejection (sso.go) -- untested before this file: a suspended or
// deactivated account must be refused an SSO session even though the IdP
// itself authenticated the identity successfully.
package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCompleteSSO_DeactivatedAccount_Rejected(t *testing.T) {
	c, store, key, p := ssoTestCore(t)
	deactivated := &models.User{ID: 88, IsActive: false, AccountState: "active"}

	const testNonce = "nonce-deactivated"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "okta|88",
		"email": "deactivated@x.io", "email_verified": true, "nonce": testNonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-deact").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|88").Return(deactivated, nil)

	session, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-deact", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

func TestCompleteSSO_SuspendedAccount_Rejected(t *testing.T) {
	c, store, key, p := ssoTestCore(t)
	suspended := &models.User{ID: 89, IsActive: true, AccountState: AccountSuspended}

	const testNonce = "nonce-suspended"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "okta|89",
		"email": "suspended@x.io", "email_verified": true, "nonce": testNonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-susp").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|89").Return(suspended, nil)

	session, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-susp", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}
