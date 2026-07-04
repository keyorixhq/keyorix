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
		// #117: issue+deliver now runs detached in a background goroutine so the
		// call returns at the same speed regardless of whether the email exists
		// (closing the SMTP-send timing oracle) — done synchronizes this
		// assertion with that async work instead of racing it.
		done := make(chan struct{})
		fake := &fakeDeliverer{echoLink: true, result: delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, done: done}
		c, ms := newCore(fake)
		ms.On("GetUserByEmail", ctx, email).Return(activeUser, nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-24*time.Hour)).Return(int64(0), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-resendMinInterval)).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposePasswordResetLink, email).Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

		require.NoError(t, c.RequestPasswordReset(ctx, email))
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the background delivery")
		}
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

	// TestRequestPasswordReset_KnownEmailReturnsWithoutWaitingForDelivery pins
	// #117: the known-account path used to synchronously dial-and-send the
	// email before returning, while an unknown address returned after a single
	// fast DB lookup — a measurable timing side-channel. RequestPasswordReset
	// must now return promptly for a KNOWN email even when delivery is slow,
	// proving delivery no longer blocks the response.
	t.Run("known email returns without waiting for a slow delivery", func(t *testing.T) {
		deliveryStarted := make(chan struct{})
		releaseDelivery := make(chan struct{})
		slow := &slowFakeDeliverer{started: deliveryStarted, release: releaseDelivery}
		c, ms := newCore(slow)
		ms.On("GetUserByEmail", ctx, email).Return(activeUser, nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-24*time.Hour)).Return(int64(0), nil)
		ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-resendMinInterval)).Return(int64(0), nil)
		ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposePasswordResetLink, email).Return(nil)
		ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)
		defer close(releaseDelivery) // don't leak the goroutine if the test fails early

		done := make(chan struct{})
		go func() {
			require.NoError(t, c.RequestPasswordReset(ctx, email))
			close(done)
		}()

		select {
		case <-done:
			// RequestPasswordReset returned — good, it did not wait for delivery.
		case <-time.After(2 * time.Second):
			t.Fatal("RequestPasswordReset blocked on delivery instead of returning immediately")
		}
		// The delivery genuinely started (proves the goroutine wasn't just skipped).
		select {
		case <-deliveryStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("background delivery never started")
		}
	})
}

// slowFakeDeliverer blocks inside DeliverSetupLink until release is closed, so a
// test can prove a caller does NOT wait for it.
type slowFakeDeliverer struct {
	started chan struct{}
	release chan struct{}
}

func (s *slowFakeDeliverer) DeliverSetupLink(_ context.Context, _ delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	close(s.started)
	<-s.release
	return delivery.DeliveryResult{Channel: delivery.ChannelSMTP, Delivered: true}, nil
}

func (s *slowFakeDeliverer) Name() string { return "slow-fake" }

// panicDeliverer panics inside DeliverSetupLink to simulate a bug surfacing
// in the detached goroutine RequestPasswordReset spawns to issue+deliver the
// reset link.
type panicDeliverer struct {
	done chan struct{}
}

func (p *panicDeliverer) DeliverSetupLink(_ context.Context, _ delivery.SetupLinkRequest) (delivery.DeliveryResult, error) {
	defer close(p.done)
	panic("simulated panic in credential delivery")
}

func (p *panicDeliverer) Name() string { return "panic-fake" }

// TestRequestPasswordReset_PanicInDetachedGoroutineDoesNotCrash proves backlog
// #481: RequestPasswordReset issues+delivers the reset link from a detached
// goroutine (#117, closing a timing side-channel), reachable by a completely
// unauthenticated caller via POST /auth/password-reset. Before this fix, that
// goroutine was a bare `go func(){...}()` with no panic recovery — a panic
// there is NOT caught by the HTTP server's per-request recovery middleware
// (which only guards the goroutine serving the request) and crashes the
// entire process for every connected tenant. If goSafe's recover() didn't
// wrap this call site, this test binary itself would crash before reaching
// the assertions below.
func TestRequestPasswordReset_PanicInDetachedGoroutineDoesNotCrash(t *testing.T) {
	ctx := context.Background()
	const email = "reset-panic@acme.io"
	fixed := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

	done := make(chan struct{})
	panicker := &panicDeliverer{done: done}
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.now = func() time.Time { return fixed }
	c.SetCredentialDelivery(panicker, testBaseURL)
	anyAudit(ms)

	activeUser := &models.User{ID: 11, Email: email, DisplayName: "Panicker", AccountState: AccountActive}
	ms.On("GetUserByEmail", ctx, email).Return(activeUser, nil)
	ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-24*time.Hour)).Return(int64(0), nil)
	ms.On("CountSetupTokensSince", ctx, SetupPurposePasswordResetLink, email, fixed.Add(-resendMinInterval)).Return(int64(0), nil)
	ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposePasswordResetLink, email).Return(nil)
	ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).Return(&models.SetupToken{ID: 1}, nil)

	// The enumeration-safe contract holds regardless: RequestPasswordReset
	// always returns nil.
	require.NoError(t, c.RequestPasswordReset(ctx, email))

	select {
	case <-done:
		// The detached goroutine panicked and goSafe's recover() caught it —
		// the process (and this test binary) is still alive to reach here.
	case <-time.After(2 * time.Second):
		t.Fatal("detached delivery goroutine never ran")
	}
}
