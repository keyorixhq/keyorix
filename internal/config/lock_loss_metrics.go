package config

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// advisoryLockLost counts lock losses ReportAdvisoryLockLost reports, by kind of
// lock, so a loss is alertable and not only a log line (POOLER-LOCKLOSS-1).
// A loss of a per-section lock (named, scheduler, ...) leaves the server
// running, so the counter is scraped; a lost presence or single_writer lock
// ends the process right after, so for those the restart is the signal and the
// counter is only seen if a scrape lands in between.
var advisoryLockLost = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_advisory_lock_lost_total",
	Help: "PostgreSQL advisory locks found lost while held (their connection died), by lock: presence, admin_exclusive, single_writer, key_init, named, scheduler, bootstrap, audit_checkpoint, audit_index_build, other.",
}, []string{"lock"})

// lockLossKinds maps the who prefix each holder passes to ReportAdvisoryLockLost
// to the bounded lock label. A who that matches none is counted as other
// (TestLockLossKind_EveryHolderIsNamed lists every holder's who).
var lockLossKinds = []struct{ prefix, kind string }{
	{"serverguard presence lock", "presence"},
	{"serverguard admin exclusive lock", "admin_exclusive"},
	{"single_writer holder lock", "single_writer"},
	{"key-initialisation lock", "key_init"},
	{"named lock", "named"},
	{"scheduler lock", "scheduler"},
	{"bootstrap lock", "bootstrap"},
	{"audit-checkpoint lock", "audit_checkpoint"},
	{"audit index build lock", "audit_index_build"},
}

func init() {
	// Every series exists from start-up at 0, so an alert on increase() fires
	// on the first loss.
	for _, k := range lockLossKinds {
		advisoryLockLost.WithLabelValues(k.kind)
	}
	advisoryLockLost.WithLabelValues("other")
}

// lockLossKind returns the lock label for who.
func lockLossKind(who string) string {
	for _, k := range lockLossKinds {
		if strings.HasPrefix(who, k.prefix) {
			return k.kind
		}
	}
	return "other"
}
