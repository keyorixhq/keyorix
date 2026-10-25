package core

// owed_audit_collect_only_crash_test.go — RD-TLA-OWED-FIX-1. TLC found it
// (docs/formal/owed-audit/pendingfault_silent.cfg): the pending_audit_events
// record of an owed row is refused inside the revocation's transaction, so the
// revocation commits through the collect-only fallback with its rows held only in
// memory. The process then dies before the rows are appended. Before this fix the
// rows were queued late only AFTER a failed append (up to the 5 s wait later), so the
// crash lost them with no record, and no log line named them.
//
// Now:
//   - the late record is written right after the commit, before the append wait,
//     so a crash at the append leaves a durable owed record (the backfill writes it,
//     after a restart too);
//   - the rows are named in a SECURITY line BEFORE the commit, so if the late record
//     cannot be written either (the pending table still refuses) or the process dies
//     before it, the loss is loud, never silent.
//
// "Crash" is runtime.Goexit at the first audit append (crashAtAuditStorage's
// stand-in for kill -9), "restart" a new core over a new storage handle.

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// collectOnlyCrashHooks refuses the first `refuse` CreatePendingAuditEvent calls (0:
// every call) and ends the goroutine at the first LogAuditEvent.
func collectOnlyCrashHooks(refuse int32) *storeHooks {
	var records atomic.Int32
	var crashed atomic.Bool
	return &storeHooks{
		WrapTx: true,
		CreatePendingAuditEvent: func(next storage.Storage, ctx context.Context, p *models.PendingAuditEvent) error {
			if n := records.Add(1); refuse == 0 || n <= refuse {
				return errors.New("injected fault: pending_audit_events refuses writes")
			}
			return next.CreatePendingAuditEvent(ctx, p)
		},
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if crashed.CompareAndSwap(false, true) {
				runtime.Goexit()
			}
			return next.LogAuditEvent(ctx, e)
		},
	}
}

// Not parallel: captures the global logger.
func TestOwedAudit_CollectOnlyCommitThenCrash_RowsQueuedBeforeTheAppend(t *testing.T) {
	ctx := context.Background()

	t.Run("revocation (runOwedAuditMutation)", func(t *testing.T) {
		smaBackends(t, func(t *testing.T, sw *smaWorld) {
			w := newSATWorld(t, sw.f)
			st := w.f.setup.Storage()
			envScope := Scope{ProjectID: w.f.projectID, EnvironmentID: w.f.envID}

			t.Run("record refused once: a crash at the append leaves the rows queued", func(t *testing.T) {
				u := w.newUser("cocrash", "project_viewer")
				require.NoError(t, st.AssignRole(ctx, u.ID, w.devRole.ID, envScope))
				c := NewKeyorixCore(hooked(w.fs, collectOnlyCrashHooks(1)))
				pending, removed := w.pendingTotal(), w.eventRows(EventRoleRemoved)

				returned, err := runCrashing(func() error { return c.RemoveProjectMember(ctx, w.f.adminID, w.f.projectID, u.ID) })
				require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
				require.Empty(t, lateQueueRoles(t, st, u.ID, envScope), "the revocation committed before the append")
				require.Equal(t, removed, w.eventRows(EventRoleRemoved))
				require.Equal(t, pending+2, w.pendingTotal(), "both owed rows must be durably queued before the append")

				restarted := NewKeyorixCore(localstore.NewLocalStorage(w.db))
				n, berr := restarted.BackfillPendingAuditEvents(ctx)
				require.NoError(t, berr)
				require.Equal(t, 2, n)
				require.Equal(t, removed+2, w.eventRows(EventRoleRemoved), "every owed row is in the chain after the restart")
				require.Equal(t, pending, w.pendingTotal())
			})

			t.Run("record refused always: the rows are named before the commit (loud, not silent)", func(t *testing.T) {
				u := w.newUser("cocrash-gap", "project_viewer")
				require.NoError(t, st.AssignRole(ctx, u.ID, w.devRole.ID, envScope))
				c := NewKeyorixCore(hooked(w.fs, collectOnlyCrashHooks(0)))
				logs := captureOwedAuditLog(t)
				pending := w.pendingTotal()

				returned, err := runCrashing(func() error { return c.RemoveProjectMember(ctx, w.f.adminID, w.f.projectID, u.ID) })
				require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
				require.Empty(t, lateQueueRoles(t, st, u.ID, envScope), "a revocation is never blocked by the audit ledger")
				require.Equal(t, pending, w.pendingTotal(), "the pending table refused every write")
				out := logs.String()
				require.Equal(t, 2, strings.Count(out, `SECURITY: owed audit event "`+EventRoleRemoved+`"`),
					"each owed row must be named in a SECURITY line written before the process could die:\n%s", out)
				require.Contains(t, out, "lost if the process stops before it is written")
			})

			v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
			require.NoError(t, err)
			require.True(t, v.Valid, v.Reason)
		})
	})

	t.Run("plain suspend (commitOwingAudit)", func(t *testing.T) {
		t.Run("record refused once: a crash at the append leaves the row queued", func(t *testing.T) {
			w := newOwedAuditWorld(t)
			id := w.secret(t, "cocrash", 1, SecretStatusActive, false)
			c := NewKeyorixCore(hooked(w.c.storage, collectOnlyCrashHooks(1)))

			returned, err := runCrashing(func() error { _, err := c.SuspendSecret(ctx, id, 1, "incident 7"); return err })
			require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
			require.Equal(t, SecretStatusSuspended, w.stored(t, id).Status)
			require.Empty(t, w.events(t, EventSecretSuspended))
			p := w.pending(t)
			require.Len(t, p, 1, "the owed row must be durably queued before the append")
			require.Contains(t, p[0].Event, "incident 7")

			restarted := NewKeyorixCore(localstore.NewLocalStorage(w.db))
			n, berr := restarted.BackfillPendingAuditEvents(ctx)
			require.NoError(t, berr)
			require.Equal(t, 1, n)
			require.Len(t, w.events(t, EventSecretSuspended), 1)
			require.Empty(t, w.pending(t))
			w.chainValid(t)
		})

		t.Run("record refused always: the row is named before the effect (loud, not silent)", func(t *testing.T) {
			w := newOwedAuditWorld(t)
			id := w.secret(t, "cocrash-gap", 1, SecretStatusActive, false)
			c := NewKeyorixCore(hooked(w.c.storage, collectOnlyCrashHooks(0)))
			logs := captureOwedAuditLog(t)

			returned, err := runCrashing(func() error { _, err := c.SuspendSecret(ctx, id, 1, "incident 8"); return err })
			require.False(t, returned, "precondition: the goroutine must have died at the append (returned err=%v)", err)
			require.Equal(t, SecretStatusSuspended, w.stored(t, id).Status)
			require.Empty(t, w.pending(t))
			out := logs.String()
			require.Contains(t, out, `SECURITY: owed audit event "`+EventSecretSuspended+`"`)
			require.Contains(t, out, "incident 8")
			require.Contains(t, out, "lost if the process stops before it is written")
		})
	})
}
