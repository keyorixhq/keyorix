package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failBreakGlassGrantStorage always fails AssignRoleWithExpiry (forcing
// ActivateBreakGlass's compensating-revert path) and fails
// UpdateBreakGlassActivation once (the revert's OWN write), mirroring the
// failOnceStorage idiom from #2295.
type failBreakGlassGrantStorage struct {
	storage.Storage
	revertArmed *bool
}

func (s *failBreakGlassGrantStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	return errors.New("injected fault: AssignRoleWithExpiry")
}

func (s *failBreakGlassGrantStorage) UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error {
	if *s.revertArmed {
		*s.revertArmed = false
		return errors.New("injected fault: UpdateBreakGlassActivation (the revert itself)")
	}
	return s.Storage.UpdateBreakGlassActivation(ctx, a)
}

// TestActivateBreakGlass_RevertFailureIsAuditedLoudly is the red-proof for
// Session O's O3 break-glass fix: when the compensating revert (reconciling
// the activation row to "revoked" after a role-grant failure) ITSELF fails,
// that must be audited loudly -- not silently swallowed (`_ =`), since a
// stuck "active" row with no real grant blocks the user's retry via the
// partial unique index, indefinitely, with no signal anywhere.
func TestActivateBreakGlass_RevertFailureIsAuditedLoudly(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "bg-proj", Description: "d"})
	require.NoError(t, err)
	u, err := st.CreateUser(ctx, foldedTestUser(t, "responder", "responder@example.com"))
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, 1, proj.ID, u.ID, "project_viewer", false))

	c.SetBreakGlassPolicy(BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})

	revertArmed := true
	c.storage = &failBreakGlassGrantStorage{Storage: st, revertArmed: &revertArmed}

	_, err = c.ActivateBreakGlass(ctx, proj.ID, u.ID, "prod incident, needs immediate access", "")
	require.Error(t, err)
	require.False(t, revertArmed, "the injected revert fault must actually have fired")

	events, _, eerr := st.GetAuditLogs(ctx, &storage.AuditFilter{})
	require.NoError(t, eerr)
	var loggedTypes []string
	for _, e := range events {
		loggedTypes = append(loggedTypes, e.EventType)
	}
	assert.Contains(t, loggedTypes, "break_glass.activation_revert_failed",
		"a failed compensating revert must be audited loudly, not silently swallowed")
}
