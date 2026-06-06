package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRequestPasswordReset(t *testing.T) {
	ctx := context.Background()
	const email = "reset@acme.io"
	fixed := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

	newCore := func(d delivery.CredentialDelivery) (*KeyorixCore, *MockStorage) {
		ms := new(MockStorage)
		c := NewKeyorixCore(ms)
		c.now = func() time.Time { return fixed }
		c.SetCredentialDelivery(d, testBaseURL)
		anyAudit(ms)
		return c, ms
	}
	activeUser := &models.User{ID: 9, Email: email, DisplayName: "Rhea", AccountState: AccountActive}

	t.Run("active account: issues a password_reset_link and delivers it", func(t *testing.T) {
		fake := &fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}}
		c, ms := newCore(fake)
		ms.On("GetUserByEmail", ctx, email).Return(activeUser, nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-24*time.Hour)).Return(int64(0), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-resendMinInterval)).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposePasswordResetLink, email).Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		require.NoError(t, c.RequestPasswordReset(ctx, email))
		assert.True(t, fake.called, "the reset link should be delivered")
		assert.Equal(t, SetupPurposePasswordResetLink, fake.lastReq.Purpose)
		assert.Equal(t, email, fake.lastReq.RecipientEmail)
		ms.AssertCalled(t, "CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken"))
	})

	t.Run("unknown email: no token, no delivery, no leak", func(t *testing.T) {
		fake := &fakeDeliverer{}
		c, ms := newCore(fake)
		ms.On("GetUserByEmail", ctx, "nobody@acme.io").Return(nil, fmt.Errorf("not found"))

		require.NoError(t, c.RequestPasswordReset(ctx, "nobody@acme.io"))
		assert.False(t, fake.called)
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("suspended account: no reset link issued", func(t *testing.T) {
		fake := &fakeDeliverer{}
		c, ms := newCore(fake)
		ms.On("GetUserByEmail", ctx, email).Return(
			&models.User{ID: 9, Email: email, AccountState: AccountSuspended}, nil)

		require.NoError(t, c.RequestPasswordReset(ctx, email))
		assert.False(t, fake.called)
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})

	t.Run("throttled: swallowed, no token issued", func(t *testing.T) {
		fake := &fakeDeliverer{}
		c, ms := newCore(fake)
		ms.On("GetUserByEmail", ctx, email).Return(activeUser, nil)
		// Over the daily cap → checkResendThrottle returns an error, swallowed.
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-24*time.Hour)).Return(int64(resendDailyCap), nil)

		require.NoError(t, c.RequestPasswordReset(ctx, email))
		assert.False(t, fake.called)
		ms.AssertNotCalled(t, "CreateSetupToken", mock.Anything, mock.Anything)
	})
}
