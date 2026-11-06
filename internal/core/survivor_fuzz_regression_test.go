package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Regression tests that kill gremlins mutants which survived the weekly run of
// internal/core. Each one comes from an input the differential survivor fuzzer
// (scripts/mutation-testing/survivor-fuzz) found that tells the original
// function from the mutated one; each states the mutation it kills.

// Kills CONDITIONALS_BOUNDARY `r > bestRank` -> `>=`: an action outside the
// ranked set has rank 0, equal to the starting rank, so a `>=` comparison would
// report an unknown action as the strongest one. It must report nothing.
func TestHighestSecretsAction_UnknownActionIsNotReported(t *testing.T) {
	t.Parallel()
	perms := []*models.Permission{{Resource: "secrets", Action: "unknown"}}
	assert.Equal(t, "", highestSecretsAction(perms))
	// Among equal ranks the first one stays; a later lower rank never replaces it.
	perms = []*models.Permission{
		{Resource: "secrets", Action: "write"},
		{Resource: "secrets", Action: "read"},
		{Resource: "other", Action: "admin"},
	}
	assert.Equal(t, "write", highestSecretsAction(perms))
}

// Kills CONDITIONALS_BOUNDARY `Sub(*set) > maxAge` -> `>=`: a password that is
// exactly MaxAgeDays old is still valid; it expires only once it is older.
func TestPasswordExpired_ExactlyAtMaxAgeIsNotExpired(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	c.passwordPolicy = PasswordPolicy{MaxAgeDays: 81}

	exactly := fixed.Add(-81 * 24 * time.Hour)
	assert.False(t, c.PasswordExpired(&models.User{PasswordChangedAt: &exactly}), "exactly MaxAgeDays old is not expired")
	older := exactly.Add(-time.Second)
	assert.True(t, c.PasswordExpired(&models.User{PasswordChangedAt: &older}), "one second past MaxAgeDays is expired")
}

// Kills CONDITIONALS_NEGATION `adminID != userID` -> `==` in RevokeUserSessions:
// the rank-ceiling check must run when the actor is somebody else. A plain user
// must not be able to force-logout the bootstrap admin; the admin's sessions stay.
func TestRevokeUserSessions_LowerRankActorCannotRevokeAdminSessions(t *testing.T) {
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	plain, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "sf-plain", Email: "sf-plain@example.com", DisplayName: "Plain",
		Password: "Tr1cky-Passphrase-For-Tests!",
	})
	require.NoError(t, err)
	for i := range 2 {
		_, err := st.CreateSession(ctx, &models.Session{UserID: admin.ID, SessionToken: fmt.Sprintf("sf-adm-%d", i), CreatedAt: time.Now()})
		require.NoError(t, err)
	}

	n, err := c.RevokeUserSessions(ctx, plain.ID, admin.ID)
	require.ErrorIs(t, err, ErrInsufficientAdminAuthority)
	assert.Zero(t, n)
	left, err := st.ListSessionsByUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Len(t, left, 2, "the refused revocation must leave the admin's sessions in place")

	// Control: the admin can revoke the plain user's sessions.
	_, err = st.CreateSession(ctx, &models.Session{UserID: plain.ID, SessionToken: "sf-plain-0", CreatedAt: time.Now()})
	require.NoError(t, err)
	n, err = c.RevokeUserSessions(ctx, admin.ID, plain.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// Kills CONDITIONALS_NEGATION `it.Decision != ReviewItemPending` -> `==` in
// checkForceCloseIndependence (ARC-002): the actor's OWN still-pending item must
// block a force-close, a decided one must not, and nobody else's item matters.
func TestCheckForceCloseIndependence_OwnPendingItemRefused(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	const actor = uint(1)

	own := &models.AccessReviewItem{Decision: ReviewItemPending, PrincipalType: "user", PrincipalID: actor}
	require.Error(t, c.checkForceCloseIndependence(ctx, actor, []*models.AccessReviewItem{own}), "own pending item blocks the force-close")

	decided := &models.AccessReviewItem{Decision: "attested", PrincipalType: "user", PrincipalID: actor}
	require.NoError(t, c.checkForceCloseIndependence(ctx, actor, []*models.AccessReviewItem{decided}), "own decided item does not")

	other := &models.AccessReviewItem{Decision: ReviewItemPending, PrincipalType: "user", PrincipalID: actor + 1}
	require.NoError(t, c.checkForceCloseIndependence(ctx, actor, []*models.AccessReviewItem{other}), "someone else's pending item does not")
}

// Kills CONDITIONALS_NEGATION `p.EscalateAfterMinutes < min` -> `>=` in
// minEscalateDelay: the result is the smallest delay, not the largest.
func TestMinEscalateDelay_ReturnsSmallest(t *testing.T) {
	t.Parallel()
	pol := func(m ...int) []models.AlertEscalationPolicy {
		out := make([]models.AlertEscalationPolicy, len(m))
		for i, v := range m {
			out[i].EscalateAfterMinutes = v
		}
		return out
	}
	assert.Equal(t, 3, minEscalateDelay(pol(5, 3, 9)))
	assert.Equal(t, 7, minEscalateDelay(pol(7)))
	assert.Equal(t, 2, minEscalateDelay(pol(2, 2, 4)))
}
