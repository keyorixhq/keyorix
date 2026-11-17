package core

// VALIDATION-TYPED-NOV-1 item 4: the i18n "ErrorValidation" refusals of break-glass and of
// the access-review campaigns match a sentinel with their text unchanged. The
// independent-reviewer refusals stay authorization refusals (ErrPermissionDenied): only the
// way a refusal is typed changed here, never whether it fires.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestValidationTyped_AccessReviewRefusals(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage)) // every case refuses before any storage call
	ctx := context.Background()
	const actor = uint(1)
	own := &models.AccessReviewItem{Decision: ReviewItemPending, PrincipalType: "user", PrincipalID: actor}
	cases := []struct {
		name string
		call func() error
	}{
		{"project report without project", func() error { _, err := c.GenerateProjectAccessReview(ctx, 0); return err }},
		{"open campaign without project", func() error { _, err := c.OpenAccessReviewCampaign(ctx, actor, 0, 0, "q"); return err }},
		{"list campaigns without project", func() error { _, err := c.ListAccessReviewCampaigns(ctx, 0); return err }},
		{"action neither attest nor revoke", func() error { _, err := targetDecisionForAction("maybe"); return err }},
		{"force-close over the actor's own pending item", func() error {
			return c.checkForceCloseIndependence(ctx, actor, []*models.AccessReviewItem{own})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrValidation)
			assert.True(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "the text is unchanged: %q", err.Error())
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}
}

// Reviewing your own access is an authorization refusal: typed ErrPermissionDenied, not a
// validation refusal, so a transport classifying by ErrValidation never reads it as one.
func TestValidationTyped_ReviewerIndependenceStaysPermissionDenied(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage))
	err := c.checkReviewerIndependence(context.Background(), 1, "user", 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPermissionDenied)
	assert.NotErrorIs(t, err, ErrValidation)
}

// The break-glass refusal of a missing project id matches ErrBreakGlassInvalidRequest
// (400 / InvalidArgument), like its siblings, with the wording the break-glass wording
// tests pin. The two emergency-role guards (install-wide admin, roles.assign) need a real
// role store: the table in server/http/handlers/validation_refusal_status_characterization_test.go
// drives them through ActivateBreakGlass.
func TestValidationTyped_BreakGlassRefusals(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage))
	ctx := context.Background()
	_, err := c.ListBreakGlassActivations(ctx, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBreakGlassInvalidRequest)
	assert.Equal(t, i18n.T("ErrorValidation", nil)+": project ID is required", err.Error())
}
