package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// actorActive4546Cases are the mutating entry points #4546 (L2 of REVIEW-4522-DEEP-1)
// found without requireActorActive: the dual-control approval, the early end of a
// break-glass grant and the close of an access-review campaign.
func actorActive4546Cases(actor uint) map[string]func(c *KeyorixCore) error {
	return map[string]func(c *KeyorixCore) error{
		"ApproveRiskException": func(c *KeyorixCore) error {
			return c.ApproveRiskException(context.Background(), actor, false, 1)
		},
		"RevokeBreakGlass": func(c *KeyorixCore) error {
			return c.RevokeBreakGlass(context.Background(), actor, 0, 1, 2)
		},
		"CloseAccessReviewCampaign": func(c *KeyorixCore) error {
			_, err := c.CloseAccessReviewCampaign(context.Background(), actor, 0, 1, 2, true)
			return err
		},
	}
}

// callPastAccountCheck runs call, reporting an unexpected storage call (the mock
// panics on one) as the entry point acting past the account check.
func callPastAccountCheck(c *KeyorixCore, call func(c *KeyorixCore) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("acted past the account check: %v", r)
		}
	}()
	return call(c)
}

// TestSuspendedActorRefused_4546: a suspended human actor is refused with
// ErrPermissionDenied before anything else is read or written. The mock answers
// only GetUser, so the exception, activation or campaign read, and every write
// after it, fails the test: the assertion is on the absence of the effect.
func TestSuspendedActorRefused_4546(t *testing.T) {
	const actor uint = 42
	for name, call := range actorActive4546Cases(actor) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := setupTestCore(t)
			m := c.storage.(*MockStorage)
			m.On("GetUser", mock.Anything, actor).Return(&models.User{ID: actor, IsActive: false, AccountState: AccountSuspended}, nil)
			err := callPastAccountCheck(c, call)
			require.ErrorIs(t, err, ErrPermissionDenied)
			m.AssertExpectations(t)
		})
	}
}

// TestActorReadFaultRefused_4546: a failed read of the acting account is a refusal
// too (fail closed), typed as a storage read fault so a transport answers 503, and
// nothing past it runs.
func TestActorReadFaultRefused_4546(t *testing.T) {
	const actor uint = 42
	for name, call := range actorActive4546Cases(actor) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := setupTestCore(t)
			m := c.storage.(*MockStorage)
			m.On("GetUser", mock.Anything, actor).Return((*models.User)(nil), errors.New("connection reset"))
			err := callPastAccountCheck(c, call)
			require.ErrorIs(t, err, ErrStorageReadUnavailable)
			require.NotErrorIs(t, err, ErrPermissionDenied)
			m.AssertExpectations(t)
		})
	}
}
