// break_glass_review_test.go -- ADR-112 §3 (secure-by-default baseline,
// break-glass review item 5): KeyorixCore.ReviewBreakGlass and
// ListUnreviewedBreakGlassActivations.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func breakGlassActivationFixture() *models.BreakGlassActivation {
	return &models.BreakGlassActivation{
		ID: 7, ProjectID: 1, UserID: 10, RoleID: 3, RoleName: "editor", State: BreakGlassActive,
	}
}

func TestReviewBreakGlass_RecordsReviewAndAudits(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)
	ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), "checked the justification, looks fine", mock.Anything).Return(nil)
	var captured *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).Return(nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "checked the justification, looks fine")
	require.NoError(t, err)

	if assert.NotNil(t, captured) {
		assert.Equal(t, EventBreakGlassReviewed, captured.EventType)
	}
}

func TestReviewBreakGlass_RejectsShortNote(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "ok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "characters")
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestReviewBreakGlass_RejectsEmptyProjectID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 0, 7, "a perfectly good review note")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

func TestReviewBreakGlass_MismatchedProjectIsNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 999, 7, "a perfectly good review note")
	require.Error(t, err)
	ms.AssertNotCalled(t, "ReviewBreakGlassActivation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Allowed regardless of activation state -- a revoked/expired activation can
// still be reviewed; ReviewBreakGlass itself performs no state guard.
func TestReviewBreakGlass_AllowedOnRevokedActivation(t *testing.T) {
	revoked := breakGlassActivationFixture()
	revoked.State = BreakGlassRevoked

	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(revoked, nil)
	ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), mock.Anything, mock.Anything).Return(nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "reviewed after revoke, looks fine")
	require.NoError(t, err)
}

func TestReviewBreakGlass_AlreadyReviewedIsSurfacedAsValidationError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetBreakGlassActivation", mock.Anything, uint(7)).Return(breakGlassActivationFixture(), nil)
	ms.On("ReviewBreakGlassActivation", mock.Anything, uint(7), uint(99), mock.Anything, mock.Anything).
		Return(storage.ErrBreakGlassAlreadyReviewed)

	c := NewKeyorixCore(ms)
	err := c.ReviewBreakGlass(context.Background(), 99, 1, 7, "trying to review a second time")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already been reviewed")
}

func TestListUnreviewedBreakGlassActivations_PassesCorrectCutoff(t *testing.T) {
	ms := new(MockStorage)
	var gotCutoff time.Time
	ms.On("ListUnreviewedBreakGlassActivationsBefore", mock.Anything, mock.AnythingOfType("time.Time")).
		Run(func(args mock.Arguments) { gotCutoff = args.Get(1).(time.Time) }).
		Return([]*models.BreakGlassActivation{breakGlassActivationFixture()}, nil)

	c := NewKeyorixCore(ms)
	window := 72 * time.Hour
	before := c.now()
	rows, err := c.ListUnreviewedBreakGlassActivations(context.Background(), window)
	require.NoError(t, err)
	assert.Len(t, rows, 1)

	// cutoff must be "now - window", not some other arithmetic.
	assert.WithinDuration(t, before.Add(-window), gotCutoff, time.Second)
}
