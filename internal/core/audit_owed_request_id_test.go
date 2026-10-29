package core

// AUDIT-REQUEST-ID-2 item 3: an owed audit row keeps the id of the request that caused
// it. The pending_audit_events record carries the server-minted request id, and the
// backfill appends the row under it, so an operator can still join the late row with the
// request's log lines (docs/specs/audit-request-id.md §10). The id stays advisory and
// server-stamped: only the storage funnel writes audit_events.request_id.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/logging"
)

const (
	owedReqIDA = "aaaaaaaaaaaaaaaaaaaaaaaa"
	owedReqIDB = "bbbbbbbbbbbbbbbbbbbbbbbb"
)

func owedRequestCtx(id string) context.Context {
	ctx, h := logging.WithHolder(context.Background())
	h.SetServerRequestID(id)
	return ctx
}

// Not parallel: captures the global logger and reads the process-wide counter.
func TestOwedAudit_BackfilledRowKeepsTheRequestID(t *testing.T) {
	t.Run("a row owed during an audit outage is backfilled with the id of the request that caused it", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		captureOwedAuditLog(t)
		a := w.secret(t, "owed-a", 1, SecretStatusActive, false)
		b := w.secret(t, "owed-b", 1, SecretStatusActive, false)

		recoverAudit := refuseSuspendAudit(t, w)
		_, err := w.c.SuspendSecret(owedRequestCtx(owedReqIDA), a, 1, "incident A")
		require.NoError(t, err, "revocation is never failed by the audit log")
		_, err = w.c.SuspendSecret(owedRequestCtx(owedReqIDB), b, 1, "incident B")
		require.NoError(t, err)

		// The outage left no audit rows and two records, each with its own request's id.
		assert.Empty(t, w.events(t, EventSecretSuspended))
		pending := w.pending(t)
		require.Len(t, pending, 2)
		byDesc := map[string]*string{}
		for _, p := range pending {
			switch {
			case strings.Contains(p.Event, "incident A"):
				byDesc["A"] = p.RequestID
			case strings.Contains(p.Event, "incident B"):
				byDesc["B"] = p.RequestID
			}
		}
		require.NotNil(t, byDesc["A"])
		require.NotNil(t, byDesc["B"])
		assert.Equal(t, owedReqIDA, *byDesc["A"])
		assert.Equal(t, owedReqIDB, *byDesc["B"])

		// The audit log recovers; the scheduler's backfill has no request of its own.
		recoverAudit()
		n, err := w.c.BackfillPendingAuditEvents(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, n)

		got := map[string]string{}
		for _, e := range w.events(t, EventSecretSuspended) {
			require.NotNil(t, e.RequestID, "the backfilled row %q lost its request id", e.Description)
			switch {
			case strings.Contains(e.Description, "incident A"):
				got["A"] = *e.RequestID
			case strings.Contains(e.Description, "incident B"):
				got["B"] = *e.RequestID
			}
		}
		assert.Equal(t, map[string]string{"A": owedReqIDA, "B": owedReqIDB}, got,
			"each backfilled row keeps the id of its own request, not the backfill's")
		w.chainValid(t)
	})

	t.Run("a row owed outside any request, or under an id the server did not mint, stays NULL", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		captureOwedAuditLog(t)
		a := w.secret(t, "owed-none", 1, SecretStatusActive, false)
		b := w.secret(t, "owed-external", 1, SecretStatusActive, false)

		recoverAudit := refuseSuspendAudit(t, w)
		_, err := w.c.SuspendSecret(context.Background(), a, 1, "no request")
		require.NoError(t, err)
		extCtx, h := logging.WithHolder(context.Background())
		h.SetRequestID("client-chosen-id") // not minted by the server
		_, err = w.c.SuspendSecret(extCtx, b, 1, "client id")
		require.NoError(t, err)
		for _, p := range w.pending(t) {
			assert.Nil(t, p.RequestID, "pending %d must not record an id the server did not mint", p.ID)
		}

		recoverAudit()
		n, err := w.c.BackfillPendingAuditEvents(owedRequestCtx(owedReqIDA)) // even a backfill run inside a request
		require.NoError(t, err)
		require.Equal(t, 2, n)
		for _, e := range w.events(t, EventSecretSuspended) {
			assert.Nil(t, e.RequestID, "%q: the backfill's own id must not leak onto an owed row", e.Description)
		}
	})

	t.Run("when the audit log works the row carries the request id as for any other event", func(t *testing.T) {
		w := newOwedAuditWorld(t)
		id := w.secret(t, "ok", 1, SecretStatusActive, false)
		_, err := w.c.SuspendSecret(owedRequestCtx(owedReqIDA), id, 1, "fine")
		require.NoError(t, err)
		evs := w.events(t, EventSecretSuspended)
		require.Len(t, evs, 1)
		require.NotNil(t, evs[0].RequestID)
		assert.Equal(t, owedReqIDA, *evs[0].RequestID)
		assert.Empty(t, w.pending(t))
	})
}

// A degraded break-glass activation owes two rows (break_glass.activated, role.assigned)
// recorded by a path of its own (activateBreakGlassDegraded): both keep the activating
// request's id through the backfill, on SQLite and PostgreSQL.
func TestBreakGlass_DegradedOwedRowsKeepTheRequestID(t *testing.T) {
	bgdBackends(t, func(t *testing.T, w *bgdWorld) {
		u := w.member()
		w.audit.Store(int32(bgdError))
		a, err := w.c.ActivateBreakGlass(owedRequestCtx(owedReqIDA), w.f.projectID, u.ID, "production outage, paging incident commander now", "")
		w.audit.Store(int32(bgdOK))
		require.NoError(t, err, "break-glass must work while the audit log refuses writes")

		owed := w.owed(a.ID)
		require.Len(t, owed, 2)
		for _, p := range owed {
			require.NotNil(t, p.RequestID, "owed %s", p.EventType)
			assert.Equal(t, owedReqIDA, *p.RequestID)
		}

		n, err := w.c.BackfillPendingAuditEvents(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, n)
		for _, typ := range []string{EventBreakGlassActivated, EventRoleAssigned} {
			rows := w.auditRows(u, typ)
			require.Len(t, rows, 1, typ)
			require.NotNil(t, rows[0].RequestID, "%s lost its request id in the backfill", typ)
			assert.Equal(t, owedReqIDA, *rows[0].RequestID)
		}
		w.requireChainValid()
	})
}
