// account_state_metrics.go — Prometheus instrumentation for
// AccountLoginBlocked's fail-closed path (ADR-025), matching the
// package-per-counter-file convention internal/notifychan/notify_metrics.go
// establishes.
//
// A blank or unrecognized users.account_state should never occur once the
// backfill (internal/storage/account_state_backfill.go) and the Postgres
// enum CHECK constraint have both run -- if this counter is ever non-zero,
// either that backfill missed a row, a non-Postgres backend has no
// schema-level backstop (SQLite, by design -- see guardAccountStateValid's
// doc), or something wrote a value outside the ADR-025 canonical set through
// a path this fix didn't anticipate. Any of those is worth a page, not a
// silent log line nobody watches.
package core

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// accountStateUnrecognizedTotal counts every AccountLoginBlocked call that
// fell through to the fail-closed default case: a blank, whitespace-only, or
// otherwise unrecognized account_state value.
var accountStateUnrecognizedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_account_state_unrecognized_total",
	Help: "Count of AccountLoginBlocked calls against a blank or unrecognized users.account_state value, failed closed.",
})
