// role_permission_generation_integrity.go — the periodic check that the
// role-permission generation triggers are still the ones this binary installed
// (TRIGGER-ROWDIGEST-1, docs/design/trigger-rowdigest.md).
//
// The per-statement proof (rolePermGenerationExpr) shows that both triggers
// exist and are ENABLE ALWAYS. It does not show what they run. The owner of
// the function (the server's own database role, no superuser needed) can
// replace its body with one that bumps nothing, re-create a trigger of the
// same name on fewer events, or DISABLE, write and ENABLE ALWAYS again inside
// one transaction, and every proof still passes. A permission then removed by
// direct SQL keeps authorizing from every warm replica's cache.
//
// Every rolePermGenerationIntegrityInterval this check reads, in one catalog
// statement:
//
//   - the definition: both triggers present, ENABLE ALWAYS, of the shape the
//     installer creates, calling a function whose body, language and settings
//     are this binary's (pgRolePermGenerationFuncOK);
//   - the row versions: tgfoid and xmin of both pg_trigger rows and of the
//     function's pg_proc row. No SQL statement can set a row's xmin back, so a
//     change undone before the next tick (the DISABLE/write/ENABLE sandwich, a
//     body replaced and restored) still shows as a new xmin. The installer
//     rewrites neither row when they are already correct, so a clean boot of
//     another replica changes nothing here.
//
// A bad definition: log, count, re-install (EnsureRolePermissionsGenerationTriggers)
// and bump the generation. Changed row versions with a good definition: log,
// count and bump. The bump invalidates every replica's cache, so whatever went
// unseen while the triggers were wrong is re-read from the live join everywhere,
// not just here. A false alarm (a catalog rewrite this file does not foresee,
// such as a pg_upgrade) costs one cache refill and changes no decision.
//
// Limits, stated: the window is one interval, for deliberate DDL only (the
// accidental states keep the per-statement proof's zero window). A superuser
// below SQL (native code, the data directory, a replaced plpgsql handler or a
// redefined pg_catalog function the body calls) is not detected. PostgreSQL
// only: on SQLite whoever can write the database file controls everything.
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/gorm"
)

// rolePermGenerationIntegrityInterval is the time between two checks (a var so
// tests can shorten it).
var rolePermGenerationIntegrityInterval = 30 * time.Second

var rolePermGenerationTamperTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_role_permission_generation_tamper_total",
	Help: "Times the role-permission generation triggers were found changed (replaced function, re-created or re-enabled trigger) and every replica's permission cache was invalidated.",
})

// rolePermGenerationIntegritySQL reads one row per generation trigger: its
// enabled state, whether its definition and its function are this binary's,
// and its row versions. One bind: the expected function body.
var rolePermGenerationIntegritySQL = func() string {
	var conds []string
	for _, t := range rolePermGenerationTables {
		conds = append(conds, "(t.tgrelid = '"+t.table+"'::regclass AND t.tgname = '"+t.trigger+"')")
	}
	return `SELECT t.tgname AS name, t.tgenabled::text AS state,
  (` + pgRolePermGenerationTriggerDefOK + `) AS def_ok,
  COALESCE(` + pgRolePermGenerationFuncOK + ` AND p.pronamespace = c.relnamespace, false) AS func_ok,
  t.tgfoid::text || ':' || t.xmin::text || ':' || COALESCE(p.xmin::text, '-') AS version
FROM pg_catalog.pg_trigger t
JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
LEFT JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE NOT t.tgisinternal AND (` + strings.Join(conds, " OR ") + `)
ORDER BY t.tgname`
}()

// rolePermGenerationIntegrityState is one reading: problem is "" when the
// definition is this binary's, version the concatenated row versions.
type rolePermGenerationIntegrityState struct {
	problem string
	version string
}

func readRolePermGenerationIntegrity(ctx context.Context, db *gorm.DB) (rolePermGenerationIntegrityState, error) {
	var rows []struct {
		Name    string
		State   string
		DefOK   bool
		FuncOK  bool
		Version string
	}
	if err := db.WithContext(ctx).Raw(rolePermGenerationIntegritySQL, postgresRolePermGenerationFuncBody).Scan(&rows).Error; err != nil {
		return rolePermGenerationIntegrityState{}, err
	}
	var st rolePermGenerationIntegrityState
	var versions, problems []string
	foid := ""
	for _, r := range rows {
		versions = append(versions, r.Name+"="+r.Version)
		switch {
		case r.State != "A":
			problems = append(problems, fmt.Sprintf("%s is not ENABLE ALWAYS (tgenabled %q)", r.Name, r.State))
		case !r.DefOK:
			problems = append(problems, r.Name+" was re-created with a different definition")
		case !r.FuncOK:
			problems = append(problems, r.Name+" calls a function that is not this release's "+rolePermGenerationFunc+"()")
		}
		f, _, _ := strings.Cut(r.Version, ":")
		if foid != "" && f != foid {
			problems = append(problems, "the triggers call different functions")
		}
		foid = f
	}
	if len(rows) != len(rolePermGenerationTables) {
		problems = append(problems, fmt.Sprintf("%d of %d triggers present", len(rows), len(rolePermGenerationTables)))
	}
	st.problem = strings.Join(problems, "; ")
	st.version = strings.Join(versions, ",")
	return st, nil
}

// rolePermGenerationIntegrityChecker holds the last good reading of one
// store's database.
type rolePermGenerationIntegrityChecker struct {
	ls       *LocalStorage
	logf     func(string, ...any)
	baseline string
	// pending is set when a tick has seen a change and cleared only once the
	// repair and generation bump have committed and the definition reads as
	// this release's again. While it is set every tick repairs and bumps,
	// whatever the catalog now shows: a failed repair must not let the next
	// tick adopt whatever it reads as a fresh baseline, or a replace that is
	// restored after the failed attempt leaves every warm cache stale with
	// nothing left to see (fail closed).
	pending bool
}

// check runs one tick and reports whether it invalidated the caches. The
// first tick records the baseline (and repairs a bad definition like any
// other tick).
func (c *rolePermGenerationIntegrityChecker) check(ctx context.Context) (bool, error) {
	st, err := readRolePermGenerationIntegrity(ctx, c.ls.db)
	if err != nil {
		return false, fmt.Errorf("read the role-permission generation triggers: %w", err)
	}
	switch {
	case st.problem != "":
		c.logf("SECURITY: role-permission generation triggers changed outside this server: %s. Restoring them and invalidating every replica's permission cache; find who has DDL on this schema.", st.problem)
	case c.pending:
		c.logf("SECURITY: retrying the role-permission cache invalidation after a failed attempt (catalog row versions %s, last good %s).", st.version, c.baseline)
	case c.baseline == "" || st.version == c.baseline:
		c.baseline = st.version
		return false, nil
	default:
		c.logf("SECURITY: role-permission generation trigger or function rewritten outside this server (catalog row versions %s, were %s), now matching this release again. Invalidating every replica's permission cache; find who has DDL on this schema.", st.version, c.baseline)
	}
	rolePermGenerationTamperTotal.Inc()
	c.pending = true
	if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if st.problem != "" {
			if err := ensurePostgresRolePermGenerationTriggers(tx); err != nil {
				return err
			}
		}
		return bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx})
	}); err != nil {
		// pending stays set and the baseline is left alone: the next tick
		// repairs and bumps again, never adopts the current reading.
		return false, fmt.Errorf("restore the role-permission generation triggers: %w", err)
	}
	// The repair rewrote catalog rows: the next tick compares against them.
	after, err := readRolePermGenerationIntegrity(ctx, c.ls.db)
	if err != nil || after.problem != "" {
		// The bump committed, but the state after it is not known good: keep
		// pending, so the next tick bumps and re-reads again.
		return true, fmt.Errorf("role-permission generation triggers still not this release's after the repair: %q %v", after.problem, err)
	}
	c.baseline = after.version
	c.pending = false
	return true, nil
}

// StartRolePermissionsGenerationIntegrityCheck runs the check every
// rolePermGenerationIntegrityInterval in the background, the first one now.
// PostgreSQL only (a no-op on SQLite); Close stops it. A failed check is
// logged and retried at the next tick, never fatal: the per-statement proof
// still fails closed for a missing or disabled trigger in the meantime.
func (ls *LocalStorage) StartRolePermissionsGenerationIntegrityCheck(logf func(string, ...any)) {
	if ls.db.Dialector.Name() != "postgres" || ls.rolePermIntegrity != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &backgroundJob{cancel: cancel, done: make(chan struct{})}
	ls.rolePermIntegrity = job
	c := &rolePermGenerationIntegrityChecker{ls: ls, logf: logf}
	go func() {
		defer close(job.done)
		tick := time.NewTicker(rolePermGenerationIntegrityInterval)
		defer tick.Stop()
		for {
			if _, err := c.check(ctx); err != nil && ctx.Err() == nil {
				logf("role-permission generation integrity check: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}
