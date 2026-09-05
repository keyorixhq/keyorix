// sso_complete_success_test.go covers CompleteSSO's success tail (sso.go) --
// every existing CompleteSSO test in sso_test.go exercises a REJECTION path
// (SAML-typed provider, password-expiry-gate error, locked account). None
// reaches mintSession: the group/role sync, password-expiry no-op, session
// creation, RecordLogin, and audit-write branches were entirely untested.
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

func TestCompleteSSO_Success_MintsSessionAndAudits(t *testing.T) {
	c, store, key, p := ssoTestCore(t)
	// GroupSync/GroupRoleMap enabled with no groups claim on the token: exercises
	// CompleteSSO's own two call sites into syncSSOGroups/syncSSORoles (an absent
	// claim makes both a fast no-op internally, already covered by
	// TestSyncSSOGroups/TestSyncSSORoles's own dedicated tests elsewhere).
	p.GroupSync = true
	p.GroupRoleMap = map[string]string{"keyorix-admins": "system_admin"}

	activeUser := &models.User{ID: 77, IsActive: true, AccountState: "active"}

	const testNonce = "nonce-success"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":            "https://idp.test",
		"aud":            "client-1",
		"sub":            "okta|77",
		"email":          "success@x.io",
		"email_verified": true,
		"nonce":          testNonce,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-ok").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ReturnTo: "/dashboard", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|77").Return(activeUser, nil)
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Return(&models.Session{ID: 1, UserID: 77, SessionToken: "sess-tok"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(77), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	session, user, returnTo, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-ok", "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, "sess-tok", session.SessionToken)
	require.NotNil(t, user)
	assert.Equal(t, uint(77), user.ID)
	assert.Equal(t, "/dashboard", returnTo)
	store.AssertCalled(t, "UpdateLastLogin", mock.Anything, uint(77), mock.Anything)

	var auditEvent *models.AuditEvent
	for _, call := range store.Calls {
		if call.Method == "LogAuditEvent" {
			auditEvent = call.Arguments.Get(1).(*models.AuditEvent)
		}
	}
	require.NotNil(t, auditEvent, "a successful SSO login must write an audit event")
	assert.Equal(t, EventSSOLogin, auditEvent.EventType)
}

// TestCompleteSSO_MintSessionError_Propagates covers the one remaining error
// branch in CompleteSSO's tail: a session-creation failure must surface as an
// error, and RecordLogin/the audit write must never run for a login that
// didn't actually complete.
func TestCompleteSSO_MintSessionError_Propagates(t *testing.T) {
	c, store, key, p := ssoTestCore(t)

	activeUser := &models.User{ID: 78, IsActive: true, AccountState: "active"}
	const testNonce = "nonce-mint-error"
	idToken := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://idp.test", "aud": "client-1", "sub": "okta|78",
		"email": "minterr@x.io", "email_verified": true, "nonce": testNonce,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"access_token":"at","token_type":"Bearer","id_token":%q}`, idToken)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL

	store.On("ConsumeSSOLoginState", mock.Anything, "state-mint-err").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: testNonce, ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:okta:okta|78").Return(activeUser, nil)
	store.On("CreateSession", mock.Anything, mock.AnythingOfType("*models.Session")).
		Return(nil, assert.AnError)

	session, _, _, err := c.CompleteSSO(context.Background(), "okta", "auth-code", "state-mint-err", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.Nil(t, session)
	store.AssertNotCalled(t, "UpdateLastLogin", mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}
