package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// userNotFound mirrors the real storage "not found" error (wrapping the typed
// storage.ErrUserNotFound sentinel, #504) that resolveSSOUser treats as "no matching
// account" (rather than a hard error), so the mock matches the real path.
func userNotFound() error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
}

// stubSAML is a SAMLAuthn whose ParseResponse returns a canned assertion — so the SAML
// login flow is tested without a live IdP or a signed response.
type stubSAML struct {
	redirect, requestID string
	info                *samlpkg.AssertionInfo
	parseErr            error

	gotRelayState string
	gotRequestIDs []string
}

func (s *stubSAML) AuthnRequest(relayState string) (string, string, error) {
	s.gotRelayState = relayState
	return s.redirect, s.requestID, nil
}

func (s *stubSAML) ParseResponse(_ *http.Request, ids []string) (*samlpkg.AssertionInfo, error) {
	s.gotRequestIDs = ids
	if s.parseErr != nil {
		return nil, s.parseErr
	}
	return s.info, nil
}

func (s *stubSAML) Metadata() ([]byte, error) { return []byte("<EntityDescriptor/>"), nil }

func samlTestCore(stub *stubSAML) (*KeyorixCore, *MockStorage) {
	store := new(MockStorage)
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: true, DefaultRole: "system_viewer"}
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	return c, store
}

func TestBeginSAML(t *testing.T) {
	stub := &stubSAML{redirect: "https://idp.example/sso?SAMLRequest=x", requestID: "req-1"}
	c, store := samlTestCore(stub)
	var stored *models.SSOLoginState
	store.On("CreateSSOLoginState", mock.Anything, mock.MatchedBy(func(s *models.SSOLoginState) bool {
		stored = s
		return true
	})).Return(nil)

	url, err := c.BeginSAML(context.Background(), "corp", "/home")
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example/sso?SAMLRequest=x", url)
	require.NotNil(t, stored)
	assert.Equal(t, "corp", stored.Provider)
	assert.Equal(t, "req-1", stored.Nonce, "the AuthnRequest ID is stored for InResponseTo")
	assert.NotEmpty(t, stored.State)
	assert.Equal(t, stored.State, stub.gotRelayState, "RelayState is the login-state key")
}

func TestBeginSAML_UnknownProvider(t *testing.T) {
	c, _ := samlTestCore(&stubSAML{})
	_, err := c.BeginSAML(context.Background(), "ghost", "")
	require.Error(t, err)
}

func TestCompleteSAML_ExistingUser(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|123", Email: "ada@x.io", Name: "Ada"}}
	c, store := samlTestCore(stub)
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-1").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ReturnTo: "/home", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|123").Return(&models.User{ID: 7, IsActive: true}, nil)
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 7, SessionToken: "tok"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(7), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, user, returnTo, err := c.CompleteSAML(context.Background(), "corp", req, "relay-1", "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint(7), user.ID)
	assert.Equal(t, "tok", session.SessionToken)
	assert.Equal(t, "/home", returnTo)
	assert.Equal(t, []string{"req-1"}, stub.gotRequestIDs, "InResponseTo is matched against the stored request ID")
}

func TestCompleteSAML_InvalidResponseRejected(t *testing.T) {
	stub := &stubSAML{parseErr: errors.New("signature verification failed")}
	c, store := samlTestCore(stub)
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-2").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)

	_, _, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/", nil), "relay-2", "", "")
	require.ErrorContains(t, err, "signature verification failed")
}

func TestCompleteSAML_NoSubjectOrEmail(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{}}
	c, store := samlTestCore(stub)
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-3").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)

	_, _, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/", nil), "relay-3", "", "")
	require.ErrorContains(t, err, "no subject or email")
}

func TestCompleteSAML_NoAccountNoProvision(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|999", Email: "noone@x.io"}}
	store := new(MockStorage)
	// AutoProvision off → an unmatched identity is refused.
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: false}
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-4").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|999").Return((*models.User)(nil), userNotFound())
	store.On("GetUserByEmail", mock.Anything, "noone@x.io").Return((*models.User)(nil), userNotFound())

	_, _, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/", nil), "relay-4", "", "")
	require.ErrorContains(t, err, "no Keyorix account")
}

// TestCompleteSAML_NativeAdminTakeoverRejectedByDefault pins #89: SAML has no
// per-assertion equivalent of OIDC's email_verified claim — the assertion being
// IdP-signed only proves the IdP sent it, not that the IdP verified the user OWNS
// that address. CompleteSAML previously passed emailVerified=true unconditionally,
// so a self-service/low-trust SAML IdP could hijack an EXISTING native (password-
// based) admin account merely by asserting its email. Without the provider opting
// in via TrustAssertedEmail (off by default), the email fallback must not even
// query for a match — the login is refused outright (AutoProvision off here).
func TestCompleteSAML_NativeAdminTakeoverRejectedByDefault(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|evil", Email: "admin@company.com", Name: "Mallory"}}
	store := new(MockStorage)
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: false}
	require.False(t, p.TrustAssertedEmail, "precondition: opt-in is off by default")
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-5").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|evil").Return((*models.User)(nil), userNotFound())

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-5", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "no Keyorix account")
	assert.Nil(t, session)
	assert.Nil(t, user)
	// The native admin's email must never even be looked up.
	store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_CrossProviderEmailTakeoverRejected pins the SAML provider-confusion
// fix: a validly-signed assertion from provider "corp" must NOT be able to take over an
// account already bound to a different SSO provider ("azure") merely by asserting its
// email — even with auto-provisioning enabled and TrustAssertedEmail on. The login must
// fail closed and mint no session.
func TestCompleteSAML_CrossProviderEmailTakeoverRejected(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|evil", Email: "admin@x.io", Name: "Mallory"}}
	store := new(MockStorage)
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: true, TrustAssertedEmail: true}
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-6").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	// No account under corp's scoped id...
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|evil").Return((*models.User)(nil), userNotFound())
	// ...but the email belongs to an admin bound to provider "azure".
	store.On("GetUserByEmail", mock.Anything, "admin@x.io").
		Return(&models.User{ID: 1, Email: "admin@x.io", ExternalID: "sso:azure:admin-sub"}, nil)

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-6", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "different SSO provider")
	assert.Nil(t, session)
	assert.Nil(t, user)
	// The takeover must never reach session creation.
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_PasswordExpiredGateError covers the r123 expiry gate path:
// when an active user's password is expired and SetAccountState fails (storage
// error), CompleteSAML must return an error and mint no session.
func TestCompleteSAML_PasswordExpiredGateError(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|99", Email: "exp@x.io", Name: "Expired"}}
	c, store := samlTestCore(stub)
	c.passwordPolicy = PasswordPolicy{MaxAgeDays: 1}
	expiredUser := &models.User{ID: 99, IsActive: true, AccountState: "active", CreatedAt: time.Now().Add(-48 * time.Hour)}

	store.On("ConsumeSSOLoginState", mock.Anything, "relay-exp").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|99").Return(expiredUser, nil)
	store.On("SetAccountState", mock.Anything, uint(99), AccountPasswordResetRequired, mock.Anything).
		Return(errors.New("db unavailable"))

	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, _, _, err := c.CompleteSAML(context.Background(), "corp", req, "relay-exp", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "password expiry")
	assert.Nil(t, session)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_JITProvisionDoesNotReuseUnverifiedEmailMatch is the #89
// regression at the CompleteSAML (not just provisionSSOUser) level, for the
// AutoProvision=true path specifically: CompleteSAML previously passed a
// hardcoded emailVerified=true into provisionSSOUser regardless of the
// provider's own TrustAssertedEmail setting, so provisionSSOUser's internal
// race-guard re-resolution (reusing an existing account rather than
// duplicating) would treat the SAML-asserted email as verified and silently
// take over any account matching that email — reopening the exact
// account-takeover TestCompleteSAML_NativeAdminTakeoverRejectedByDefault
// pins for the AutoProvision=false path. With TrustAssertedEmail off (the
// default), GetUserByEmail must never even be consulted, and a login from an
// attacker asserting a victim's email must provision a FRESH account bound to
// the attacker's own subject, never touching (or returning) the victim's.
func TestCompleteSAML_JITProvisionDoesNotReuseUnverifiedEmailMatch(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|evil", Email: "victim@corp.com", Name: "Mallory"}}
	store := new(MockStorage)
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: true, DefaultRole: "system_viewer"}
	require.False(t, p.TrustAssertedEmail, "precondition: opt-in is off by default")
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-8").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|evil").Return((*models.User)(nil), userNotFound())
	store.On("GetUserByUsername", mock.Anything, "victim").Return((*models.User)(nil), userNotFound())
	var created *models.User
	store.On("CreateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool { created = u; return true })).
		Return(&models.User{ID: 99, IsActive: true}, nil)
	store.On("GetRoleByName", mock.Anything, "system_viewer").Return(&models.Role{ID: 3}, nil)
	store.On("AssignRole", mock.Anything, uint(99), uint(3), mock.Anything).Return(nil)
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 99, SessionToken: "tok"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(99), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-8", "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint(99), user.ID, "must be the fresh account, never the victim's")
	assert.Equal(t, "tok", session.SessionToken)
	require.NotNil(t, created)
	assert.Equal(t, "sso:corp:corp|evil", created.ExternalID, "fresh account bound to the asserting subject")
	store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything, "an unverified email must never even be looked up")
	store.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, "the victim account must never be claimed")
}

// TestCompleteSAML_TrustAssertedEmailOptInLinksExistingAccount is the positive
// control: an operator who has decided to trust a specific SAML provider's
// asserted email can still opt in, and the existing (never-federated) account
// linking behavior works exactly as it does for a verified OIDC email.
func TestCompleteSAML_TrustAssertedEmailOptInLinksExistingAccount(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|123", Email: "ada@x.io", Name: "Ada"}}
	store := new(MockStorage)
	p := &SSOProvider{Name: "corp", Type: "saml", SAML: stub, AutoProvision: true, TrustAssertedEmail: true}
	c := &KeyorixCore{storage: store, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-7").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|123").Return((*models.User)(nil), userNotFound())
	store.On("GetUserByEmail", mock.Anything, "ada@x.io").Return(&models.User{ID: 9, IsActive: true, ExternalID: ""}, nil)
	store.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == 9 && u.ExternalID == "sso:corp:corp|123"
	})).Return(&models.User{ID: 9, IsActive: true, ExternalID: "sso:corp:corp|123"}, nil)
	store.On("CreateSession", mock.Anything, mock.Anything).Return(&models.Session{ID: 1, UserID: 9, SessionToken: "tok"}, nil)
	store.On("UpdateLastLogin", mock.Anything, uint(9), mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-7", "ua", "1.2.3.4")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, uint(9), user.ID)
	assert.Equal(t, "tok", session.SessionToken)
}
