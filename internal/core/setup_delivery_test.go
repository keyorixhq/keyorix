package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeDeliverer is a controllable CredentialDelivery for tests. When echoLink is set
// it copies the request link into LinkForAdmin (out-of-band behaviour); otherwise it
// returns the configured result verbatim.
type fakeDeliverer struct {
	called   bool
	lastReq  delivery.SetupLinkRequest
	result   delivery.DeliveryResult
	echoLink bool
	err      error
}

func (f *fakeDeliverer) DeliverSetupLink(_ context.Context, req delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	f.called = true
	f.lastReq = req
	res := f.result
	if f.echoLink {
		res.LinkForAdmin = req.Link
	}
	return res, f.err
}

func (f *fakeDeliverer) Name() string { return "fake" }

const testBaseURL = "https://keyorix.test"

func TestResendAccountSetupLink(t *testing.T) {
	ctx := context.Background()
	uid := uint(4)
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	newCore := func(d delivery.CredentialDelivery) (*KeyorixCore, *MockStorage) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		c.SetCredentialDelivery(d, testBaseURL)
		anyAudit(ms)
		return c, ms
	}
	user := func() *models.User {
		return &models.User{ID: uid, Email: "new@acme.io", DisplayName: "Dana", AccountState: AccountPendingFirstLogin}
	}

	t.Run("out-of-band returns the built link and audits the display", func(t *testing.T) {
		fake := &fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand}}
		c, ms := newCore(fake)
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(0), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-resendMinInterval)).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "new@acme.io").Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		res, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.NoError(t, err)
		assert.True(t, fake.called)
		assert.Equal(t, delivery.ChannelOutOfBand, res.Channel)
		assert.False(t, res.Delivered)
		assert.True(t, strings.HasPrefix(res.LinkForAdmin, testBaseURL+"/auth/setup/"+setupPrefix),
			"link is base_url + /auth/setup/ + a kx_setup_ token, got %q", res.LinkForAdmin)
		// The out-of-band display is recorded as a human seeing a credential.
		ms.AssertCalled(t, "LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "credential.displayed_out_of_band"
		}))
	})

	t.Run("smtp delivery reports delivered with no admin link", func(t *testing.T) {
		fake := &fakeDeliverer{result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}
		c, ms := newCore(fake)
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", mock.AnythingOfType("time.Time")).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "new@acme.io").Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		res, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.NoError(t, err)
		assert.True(t, res.Delivered)
		assert.Empty(t, res.LinkForAdmin)
		// The recipient sees the right link in the email.
		assert.True(t, strings.HasPrefix(fake.lastReq.Link, testBaseURL+"/auth/setup/"))
	})

	t.Run("min-interval throttle blocks a too-soon resend", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(1), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-resendMinInterval)).Return(int64(1), nil)

		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wait")
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("daily-cap throttle blocks once the cap is hit", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(user(), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposeAccountSetup, "new@acme.io", fixed.Add(-24*time.Hour)).Return(int64(resendDailyCap), nil)

		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "limit")
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("rejects a suspended account", func(t *testing.T) {
		c, ms := newCore(&fakeDeliverer{})
		ms.On("GetUser", ctx, uid).Return(&models.User{ID: uid, AccountState: AccountSuspended}, nil)
		_, err := c.ResendAccountSetupLink(ctx, uid, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")
	})
}

func TestProvisionRequiresBaseURL(t *testing.T) {
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetCredentialDelivery(&fakeDeliverer{}, "") // no base URL

	req := CreateUserRequest{Username: "dana", Email: "dana@acme.io", DisplayName: "Dana"}
	_, _, err := c.CreateUserWithSetupLink(ctx, &req, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_url")
	ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

func TestCreateUserWithSetupLink(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetCredentialDelivery(&fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelOutOfBand}}, testBaseURL)
	anyAudit(ms)

	notFound := func() error { return assertNotFoundErr() }
	created := &models.User{ID: 9, Username: "dana", Email: "dana@acme.io", DisplayName: "Dana"}

	ms.On("GetUserByUsername", ctx, "dana").Return(nil, notFound())
	ms.On("GetUserByEmail", ctx, "dana@acme.io").Return(nil, notFound())
	ms.On("CreateUser", ctx, mock.AnythingOfType("*models.User")).Return(created, nil)
	ms.On("AddPasswordHistory", ctx, uint(9), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	ms.On("GetRoleByName", ctx, "system_viewer").Return(nil, notFound())
	ms.On("UpdateUser", ctx, mock.AnythingOfType("*models.User")).Return(created, nil)
	ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "dana@acme.io").Return(nil)
	ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	user, prov, err := c.CreateUserWithSetupLink(ctx, &CreateUserRequest{
		Username: "dana", Email: "dana@acme.io", DisplayName: "Dana",
	}, 7)
	require.NoError(t, err)
	assert.Equal(t, AccountPendingFirstLogin, user.AccountState, "account is confined until the link is consumed")
	require.NotNil(t, prov)
	assert.True(t, strings.HasPrefix(prov.LinkForAdmin, testBaseURL+"/auth/setup/"+setupPrefix))
}

// helpers ---------------------------------------------------------------------

// assertNotFoundErr returns an error whose message contains the not-found marker
// CreateUser checks for, so the "does this user already exist?" probes read as absent.
func assertNotFoundErr() error {
	return &notFoundError{msg: i18n.T("ErrorUserNotFound", nil)}
}

type notFoundError struct{ msg string }

func (e *notFoundError) Error() string { return e.msg }
