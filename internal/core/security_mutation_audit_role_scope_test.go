package core

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSecurityMutationAudit_UpdateRoleAssignableScope_ByDirection is
// TestSecurityMutationAudit_UpdateRole_ByDirection for the role's assignable
// scope (#3546 Phase 2): a change that lets the role be granted somewhere new
// (project -> any, global -> any, project <-> global) widens access and fails
// closed while the audit log is down; any -> project/global only narrows and
// is never blocked (its rows owed). SQLite and PostgreSQL.
func TestSecurityMutationAudit_UpdateRoleAssignableScope_ByDirection(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		down := &atomic.Bool{}
		c := NewKeyorixCore((&auditOutageStorage{inner: w.fs, down: down}).store())

		for _, tc := range []struct {
			name     string
			from, to string
			widens   bool
		}{
			{name: "project-to-any", from: models.RoleAssignableProject, to: models.RoleAssignableAny, widens: true},
			{name: "global-to-any", from: models.RoleAssignableGlobal, to: models.RoleAssignableAny, widens: true},
			{name: "project-to-global", from: models.RoleAssignableProject, to: models.RoleAssignableGlobal, widens: true},
			{name: "any-to-project", from: models.RoleAssignableAny, to: models.RoleAssignableProject},
			{name: "any-to-global", from: models.RoleAssignableAny, to: models.RoleAssignableGlobal},
			{name: "unchanged", from: models.RoleAssignableProject, to: models.RoleAssignableProject},
		} {
			t.Run(tc.name+"/audit-down", func(t *testing.T) {
				r, _, err := w.c.CreateRoleWithScope(ctx, w.f.adminID, w.tag("sat-scope"), "before", []uint{w.permID}, tc.from)
				require.NoError(t, err)
				before := w.fingerprint()
				upd := *r
				upd.AssignableScope = tc.to
				down.Store(true)
				_, _, err = c.UpdateRole(ctx, w.f.adminID, &upd, nil)
				down.Store(false)
				got, gerr := w.f.setup.Storage().GetRole(ctx, r.ID)
				require.NoError(t, gerr)
				if tc.widens {
					require.ErrorIs(t, err, ErrMutationAuditUnavailable, "a widening scope change must fail closed while the audit log is down")
					require.Equal(t, tc.from, got.AssignableScope)
					require.Equal(t, before, w.fingerprint(), "a refused widening changed state")
					return
				}
				require.NoError(t, err, "a narrowing or unchanged scope was blocked by the audit log")
				require.Equal(t, tc.to, got.AssignableScope)
			})
		}

		t.Run("widen/audit-up-recorded", func(t *testing.T) {
			r, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("sat-scope"), "", []uint{w.permID})
			require.NoError(t, err)
			rows := w.eventRows(EventRoleUpdated)
			upd := *r
			upd.AssignableScope = models.RoleAssignableAny
			_, _, err = c.UpdateRole(ctx, w.f.adminID, &upd, nil)
			require.NoError(t, err)
			require.Equal(t, rows+1, w.eventRows(EventRoleUpdated))
			got, err := w.f.setup.Storage().GetRole(ctx, r.ID)
			require.NoError(t, err)
			require.Equal(t, models.RoleAssignableAny, got.AssignableScope)
		})
	})
}
