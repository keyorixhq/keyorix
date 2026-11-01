package core

// audit_failed_panic_recover_test.go — INVARIANT-GUARDS-1 observation 4.
//
// writeAuditEventFailed is called from deny-path audits (the request's answer is
// already decided) and from post-commit best-effort steps. A panic while writing
// the audit row must not replace that answer: it is logged, counted in
// keyorix_best_effort_failures_total{step="audit.writeAuditEventFailed"}, and the
// caller returns exactly what it would have returned.
//
// Two places a panic can start, and why both are pinned:
//   - the storage write (LogAuditEvent): emitAudit already recovered this before
//     the fix, so this case is a regression pin, green on main too;
//   - building the event from ctx (actorTypeFromContext, impersonatorFromContext),
//     which runs in writeAuditEventFailed's own frame before emitAudit's recover
//     begins: this one escaped to the caller on main.

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// panickingAuditStorage serves one pending risk exception and panics on every
// audit write. Any other storage call is an unexpected call on the mock and
// panics too, which would fail the test loudly rather than pass it.
func panickingAuditStorage(exception *models.RiskException) storage.Storage {
	ms := new(MockStorage)
	ms.On("GetRiskException", mock.Anything, exception.ID).Return(exception, nil)
	return hooked(ms, &storeHooks{
		LogAuditEvent: func(storage.Storage, context.Context, *models.AuditEvent) error {
			panic("injected audit storage panic")
		},
	})
}

// panicOnImpersonationCtx panics when the impersonation tag is read. Only the
// audit event builders read that key (impersonatorFromContext), so the panic
// lands inside event construction and nowhere else on the deny path.
type panicOnImpersonationCtx struct{ context.Context }

func (c panicOnImpersonationCtx) Value(key any) any {
	if _, ok := key.(impersonationKey); ok {
		panic("injected panic building the audit event")
	}
	return c.Context.Value(key)
}

// bestEffortFailures reads keyorix_best_effort_failures_total for one step from
// the default registry (the counter is unexported in internal/besteffort).
func bestEffortFailures(t *testing.T, step string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != "keyorix_best_effort_failures_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "step" && lp.GetValue() == step {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestWriteAuditEventFailed_PanicLeavesTheDenyAnswerUnchanged(t *testing.T) {
	const step = "audit.writeAuditEventFailed"
	cases := []struct {
		name string
		ctx  context.Context
		// counted: the panic reaches writeAuditEventFailed's own recover (and is
		// counted there) rather than emitAudit's.
		counted bool
	}{
		{"storage write panics", context.Background(), false},
		{"event construction panics", panicOnImpersonationCtx{context.Background()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewKeyorixCore(panickingAuditStorage(&models.RiskException{
				ID: 7, Category: "other", CreatedBy: 1, ExpiresAt: time.Now().Add(time.Hour),
			}))
			before := bestEffortFailures(t, step)

			var err error
			require.NotPanics(t, func() {
				// A machine credential can never satisfy dual control: a pure
				// deny path whose only side effect is writeAuditEventFailed.
				err = c.ApproveRiskException(tc.ctx, 2, true, 7)
			}, "a panic writing the deny audit must not replace the deny answer")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "a machine credential cannot approve a risk exception",
				"the caller's answer must be exactly the deny it decided")

			want := before
			if tc.counted {
				want++
			}
			assert.Equal(t, want, bestEffortFailures(t, step),
				"a panic recovered by writeAuditEventFailed is counted once under %q", step)
		})
	}
}
