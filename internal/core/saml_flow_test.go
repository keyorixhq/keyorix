package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// userNotFound mirrors the storage "not found" error that resolveSSOUser treats as
// "no matching account" (rather than a hard error), so the mock matches the real path.
func userNotFound() error { return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil)) }

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
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|123").Return(&models.User{ID: 7}, nil)
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

// TestCompleteSAML_CrossProviderEmailTakeoverRejected pins the SAML provider-confusion
// fix: a validly-signed assertion from provider "corp" must NOT be able to take over an
// account already bound to a different SSO provider ("azure") merely by asserting its
// email — even with auto-provisioning enabled. The login must fail closed and mint no
// session.
func TestCompleteSAML_CrossProviderEmailTakeoverRejected(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|evil", Email: "admin@x.io", Name: "Mallory"}}
	c, store := samlTestCore(stub) // provider "corp", AutoProvision: true
	// This test exercises the cross-provider gate WITHIN the email-fallback path,
	// which is itself opt-in (TrustEmailForLinking, #89) — enable it here so the
	// fallback is reached at all, matching an operator who has decided to trust
	// this provider's asserted email for account linking.
	c.ssoProviders["corp"].TrustEmailForLinking = true
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-5").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	// No account under corp's scoped id...
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|evil").Return((*models.User)(nil), userNotFound())
	// ...but the email belongs to an admin bound to provider "azure".
	store.On("GetUserByEmail", mock.Anything, "admin@x.io").
		Return(&models.User{ID: 1, Email: "admin@x.io", ExternalID: "sso:azure:admin-sub"}, nil)

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-5", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "different SSO provider")
	assert.Nil(t, session)
	assert.Nil(t, user)
	// The takeover must never reach session creation.
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// TestCompleteSAML_NativeAdminTakeoverRejectedByDefault pins the #89 residual gap:
// even after cross-provider scoping, a SAML assertion could still hijack an
// existing NATIVE (password-based) admin account — whose external_id is empty,
// not bound to any provider — merely by asserting its email. SAML has no
// verified-email concept at all, so this is reachable with no admin-console
// access: a low-trust/self-service IdP the org configured for JIT SSO just has to
// assert the victim's address. Without TrustEmailForLinking opted in (the
// default), the email fallback must not run at all — the login is refused
// outright (AutoProvision is off here), not silently linked to the native admin.
func TestCompleteSAML_NativeAdminTakeoverRejectedByDefault(t *testing.T) {
	stub := &stubSAML{info: &samlpkg.AssertionInfo{Subject: "corp|evil", Email: "admin@company.com", Name: "Mallory"}}
	c, store := samlTestCore(stub) // provider "corp", TrustEmailForLinking defaults false
	require.False(t, c.ssoProviders["corp"].TrustEmailForLinking, "precondition: opt-in is off by default")
	c.ssoProviders["corp"].AutoProvision = false
	store.On("ConsumeSSOLoginState", mock.Anything, "relay-6").Return(
		&models.SSOLoginState{Provider: "corp", Nonce: "req-1", ExpiresAt: time.Now().Add(time.Minute)}, nil)
	store.On("GetUserByExternalID", mock.Anything, "sso:corp:corp|evil").Return((*models.User)(nil), userNotFound())

	session, user, _, err := c.CompleteSAML(context.Background(), "corp",
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil), "relay-6", "ua", "1.2.3.4")
	require.Error(t, err)
	assert.ErrorContains(t, err, "no Keyorix account")
	assert.Nil(t, session)
	assert.Nil(t, user)
	// The native admin's email must never even be looked up — the takeover surface
	// this closes is that such a lookup existed at all with no independent trust
	// signal on the asserted email.
	store.AssertNotCalled(t, "GetUserByEmail", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}
