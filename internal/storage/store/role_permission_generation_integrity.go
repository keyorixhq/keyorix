// role_permission_generation_integrity.go — the periodic check that the
// cache-validating triggers are still the ones this binary installed
// (TRIGGER-ROWDIGEST-1, docs/design/trigger-rowdigest.md): the role-permission
// generation triggers, and the secret_nodes cache-epoch trigger
// (STARTUP-GUARD-TAILS-1).
//
// The per-statement proofs (rolePermGenerationExpr, nodeTriggerExistsExpr)
// show that the triggers exist and are ENABLE ALWAYS. They do not show what
// the triggers run. The owner of the function (the server's own database
// role, no superuser needed) can replace its body with one that bumps nothing,
// re-create a trigger of the same name on fewer events, or DISABLE, write and
// ENABLE ALWAYS again inside one transaction, and every proof still passes. A
// permission then removed by direct SQL keeps authorizing from every warm
// replica's cache; a secret suspended by direct SQL keeps reading as active.
//
// Every rolePermGenerationIntegrityInterval this check reads, per target, in
// one catalog statement:
//
//   - the definition: every trigger present, ENABLE ALWAYS, of the shape the
//     installer creates, calling a function whose body, language and settings
//     are this binary's, read on a connection whose session_replication_role
//     is 'origin' (the per-statement proofs' condition,
//     pgTriggerFiresForEveryWriter);
//   - the row versions: tgfoid and xmin of the pg_trigger rows and of the
//     function's pg_proc row. No SQL statement can set a row's xmin back, so a
//     change undone before the next tick (the DISABLE/write/ENABLE sandwich, a
//     body replaced and restored) still shows as a new xmin. The installers
//     rewrite neither row when they are already correct, so a clean boot of
//     another replica changes nothing here.
//
// A bad definition: log, count, invalidate, then re-install (under a
// lock_timeout) and invalidate again. Changed row versions with a good
// definition: log, count and invalidate. Each target invalidates every
// replica's cache through the database, not this process's memory:
//
//   - role-permission generation: bump role_permissions_generation. The first
//     bump commits in its own transaction, so a repair that cannot get its
//     lock or fails outright never holds the invalidation back.
//   - secret_nodes cache epoch: move cache_epoch on every live row. That bump
//     goes through the trigger it is checking (a BEFORE trigger overwrites
//     NEW.cache_epoch), so with a bad definition it runs only after the
//     repair, in the repair's transaction; a repair that cannot commit leaves
//     the node cache unflushed until a tick's repair does.
//
// Until a repair commits and the re-read is clean every tick invalidates
// again. A false alarm (a catalog rewrite this file does not foresee, such as
// a pg_upgrade) costs one cache refill (for the cache epoch, one UPDATE of
// every live secret_nodes row per replica) and changes no decision.
//
// Limits, stated: the window is one interval (plus at most one tick timeout),
// also while a repair keeps failing, for deliberate DDL only (the accidental
// states keep the per-statement proofs' zero window). A superuser below SQL
// (native code, the data directory, a replaced plpgsql handler or a
// redefined pg_catalog function the body calls) is not detected. A session
// whose replication role is not 'origin' is reported every tick and cannot
// be repaired from here (it is a setting: ALTER ROLE/DATABASE ... SET, a DSN
// option). PostgreSQL only: on SQLite whoever can write the database file
// controls everything.
package store

import (
	"context"
	"database/sql"
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

// rolePermGenerationIntegrityTickTimeout bounds one tick, so a statement that
// hangs cannot stop the ticks after it.
var rolePermGenerationIntegrityTickTimeout = 10 * time.Second

// rolePermGenerationRepairLockTimeout is the repair's lock_timeout: how long
// its DROP TRIGGER may queue for the table's lock (stalling the table's
// readers behind it) before the repair gives up until the next tick. The
// cache-epoch invalidation's row locks use it too.
var rolePermGenerationRepairLockTimeout = time.Second

var rolePermGenerationTamperTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_role_permission_generation_tamper_total",
	Help: "Times the role-permission generation triggers were found changed (replaced function, re-created or re-enabled trigger) and every replica's permission cache was invalidated.",
})

var secretNodeCacheEpochTamperTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_secret_node_cache_epoch_tamper_total",
	Help: "Times the secret_nodes cache-epoch trigger was found changed (replaced function, re-created or re-enabled trigger) and every replica's secret metadata cache was invalidated.",
})

// triggerIntegrityTarget is one set of triggers and their function that the
// check watches.
type triggerIntegrityTarget struct {
	what  string // log noun: "role-permission generation"
	cache string // what invalidate flushes: "permission cache"
	// sql reads one row per trigger (see triggerIntegritySQL); $1 is body.
	sql      string
	body     string
	triggers int
	funcName string
	// invalidate makes every replica's cache miss, inside tx.
	invalidate func(ctx context.Context, tx *gorm.DB) error
	// invalidateNeedsRepair: invalidate goes through the trigger being
	// checked, so with a bad definition it runs only after the repair.
	invalidateNeedsRepair bool
	// repair re-installs the triggers inside tx.
	repair func(tx *gorm.DB) error
	tamper prometheus.Counter
}

type triggerSpec struct{ table, trigger string }

// triggerIntegritySQL reads one row per trigger: its enabled state, whether
// its definition and its function are this binary's, and its row versions,
// joined to this connection's session_replication_role so a row comes back
// even when no trigger does. One native bind ($1): the expected body.
func triggerIntegritySQL(triggers []triggerSpec, triggerDefOK, funcOK string) string {
	var conds []string
	for _, t := range triggers {
		conds = append(conds, "(t.tgrelid = '"+t.table+"'::regclass AND t.tgname = '"+t.trigger+"')")
	}
	return strings.Replace(`SELECT s.repl, g.name, g.state, g.def_ok, g.func_ok, g.version
FROM (SELECT pg_catalog.current_setting('session_replication_role') AS repl) s
LEFT JOIN (
  SELECT t.tgname::text AS name, t.tgenabled::text AS state,
    (`+triggerDefOK+`) AS def_ok,
    COALESCE(`+funcOK+` AND p.pronamespace = c.relnamespace, false) AS func_ok,
    t.tgfoid::text || ':' || t.xmin::text || ':' || COALESCE(p.xmin::text, '-') AS version
  FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  LEFT JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
  LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
  WHERE NOT t.tgisinternal AND (`+strings.Join(conds, " OR ")+`)
) g ON true
ORDER BY g.name`, "?", "$1", 1)
}

var rolePermGenerationIntegrityTarget = func() *triggerIntegrityTarget {
	var triggers []triggerSpec
	for _, t := range rolePermGenerationTables {
		triggers = append(triggers, triggerSpec{t.table, t.trigger})
	}
	return &triggerIntegrityTarget{
		what:     "role-permission generation",
		cache:    "permission cache",
		sql:      triggerIntegritySQL(triggers, pgRolePermGenerationTriggerDefOK, pgRolePermGenerationFuncOK),
		body:     postgresRolePermGenerationFuncBody,
		triggers: len(triggers),
		funcName: rolePermGenerationFunc,
		invalidate: func(ctx context.Context, tx *gorm.DB) error {
			return bumpRolePermissionsGenerationTx(ctx, &LocalStorage{db: tx})
		},
		repair: ensurePostgresRolePermGenerationTriggers,
		tamper: rolePermGenerationTamperTotal,
	}
}()

var secretNodeCacheEpochIntegrityTarget = &triggerIntegrityTarget{
	what:     "secret_nodes cache-epoch",
	cache:    "secret metadata cache",
	sql:      triggerIntegritySQL([]triggerSpec{{"secret_nodes", SecretNodeCacheEpochTrigger}}, pgCacheEpochTriggerDefOK, pgCacheEpochFuncOK),
	body:     postgresCacheEpochFuncBody,
	triggers: 1,
	funcName: secretNodeCacheEpochFunc,
	// Every live row: a soft-deleted row never hits (readLiveNodeStamp), and
	// undeleting it is an UPDATE the restored trigger stamps.
	invalidate: func(ctx context.Context, tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
			return err
		}
		return tx.WithContext(ctx).Exec("UPDATE secret_nodes SET cache_epoch = cache_epoch + 1 WHERE deleted_at IS NULL").Error
	},
	invalidateNeedsRepair: true,
	repair:                ensurePostgresCacheEpochTrigger,
	tamper:                secretNodeCacheEpochTamperTotal,
}

// triggerIntegrityState is one reading: problem is "" when the definition is
// this binary's and the session is in 'origin', version the concatenated row
// versions.
type triggerIntegrityState struct {
	problem string
	version string
}

// readTriggerIntegrity goes through the underlying *sql.DB, not GORM: the
// background job would otherwise run GORM's callback chain concurrently with
// anything that registers a callback on the shared *gorm.DB (tests count
// queries that way), a data race inside GORM. Only the repair path, which is
// rare, uses GORM.
func readTriggerIntegrity(ctx context.Context, db *gorm.DB, target *triggerIntegrityTarget) (triggerIntegrityState, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return triggerIntegrityState{}, err
	}
	rs, err := sqlDB.QueryContext(ctx, target.sql, target.body)
	if err != nil {
		return triggerIntegrityState{}, err
	}
	defer func() { _ = rs.Close() }()
	var versions, problems []string
	repl, foid, present := "", "", 0
	for rs.Next() {
		var name, state, version sql.NullString
		var defOK, funcOK sql.NullBool
		if err := rs.Scan(&repl, &name, &state, &defOK, &funcOK, &version); err != nil {
			return triggerIntegrityState{}, err
		}
		if !name.Valid {
			continue // the LEFT JOIN's row when no trigger exists
		}
		present++
		versions = append(versions, name.String+"="+version.String)
		switch {
		case state.String != "A":
			problems = append(problems, fmt.Sprintf("%s is not ENABLE ALWAYS (tgenabled %q)", name.String, state.String))
		case !defOK.Bool:
			problems = append(problems, name.String+" was re-created with a different definition")
		case !funcOK.Bool:
			problems = append(problems, name.String+" calls a function that is not this release's "+target.funcName+"()")
		}
		f, _, _ := strings.Cut(version.String, ":")
		if foid != "" && f != foid {
			problems = append(problems, "the triggers call different functions")
		}
		foid = f
	}
	if err := rs.Err(); err != nil {
		return triggerIntegrityState{}, err
	}
	if present != target.triggers {
		problems = append(problems, fmt.Sprintf("%d of %d triggers present", present, target.triggers))
	}
	if repl != "origin" {
		problems = append(problems, fmt.Sprintf("this server's database session runs with session_replication_role %q, not origin (ALTER ROLE/DATABASE ... SET or a connection option), so ordinary triggers and foreign keys do not fire for it", repl))
	}
	return triggerIntegrityState{problem: strings.Join(problems, "; "), version: strings.Join(versions, ",")}, nil
}

// readRolePermGenerationIntegrity reads the role-permission generation target.
func readRolePermGenerationIntegrity(ctx context.Context, db *gorm.DB) (triggerIntegrityState, error) {
	return readTriggerIntegrity(ctx, db, rolePermGenerationIntegrityTarget)
}

// triggerIntegrityChecker holds the last good reading of one target on one
// store's database.
type triggerIntegrityChecker struct {
	ls       *LocalStorage
	logf     func(string, ...any)
	target   *triggerIntegrityTarget
	baseline string
	// pending is set when a tick has seen a change and cleared only once the
	// repair and invalidation have committed and the definition reads as
	// this release's again. While it is set every tick repairs and
	// invalidates, whatever the catalog now shows: a failed repair must not
	// let the next tick adopt whatever it reads as a fresh baseline, or a
	// replace that is restored after the failed attempt leaves every warm
	// cache stale with nothing left to see (fail closed).
	pending bool
}

// check runs one tick and reports whether it invalidated the caches. The
// first tick records the baseline (and repairs a bad definition like any
// other tick).
func (c *triggerIntegrityChecker) check(ctx context.Context) (bool, error) {
	t := c.target
	st, err := readTriggerIntegrity(ctx, c.ls.db, t)
	if err != nil {
		return false, fmt.Errorf("read the %s triggers: %w", t.what, err)
	}
	switch {
	case st.problem != "":
		c.logf("SECURITY: %s triggers cannot be trusted: %s. Restoring them and invalidating every replica's %s; find who has DDL on this schema or changed the server role's database settings.", t.what, st.problem, t.cache)
	case c.pending:
		c.logf("SECURITY: retrying the %s invalidation after a failed attempt (catalog row versions %s, last good %s).", t.cache, st.version, c.baseline)
	case c.baseline == "" || st.version == c.baseline:
		c.baseline = st.version
		return false, nil
	default:
		c.logf("SECURITY: %s trigger or function rewritten outside this server (catalog row versions %s, were %s), now matching this release again. Invalidating every replica's %s; find who has DDL on this schema.", t.what, st.version, c.baseline, t.cache)
	}
	t.tamper.Inc()
	c.pending = true
	flushed := false
	if st.problem == "" || !t.invalidateNeedsRepair {
		// The invalidation commits on its own first: it never waits on, or
		// rolls back with, a repair that cannot finish.
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return t.invalidate(ctx, tx)
		}); err != nil {
			// pending stays set and the baseline is left alone: the next tick
			// invalidates (and repairs) again, never adopts the current reading.
			return false, fmt.Errorf("invalidate the %s: %w", t.cache, err)
		}
		flushed = true
	}
	if st.problem != "" {
		// The repair invalidates again in its own transaction, so a write made
		// through the wrong trigger after the first invalidation is flushed
		// when the repair commits. lock_timeout: its DROP TRIGGER takes an
		// ACCESS EXCLUSIVE lock on the table, and a request queued behind an
		// open transaction would stall every reader of the table behind it.
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
				return err
			}
			if err := t.repair(tx); err != nil {
				return err
			}
			return t.invalidate(ctx, tx)
		}); err != nil {
			// The triggers are still wrong: pending stays set, so every tick
			// invalidates again until a repair commits.
			return flushed, fmt.Errorf("restore the %s triggers: %w", t.what, err)
		}
		flushed = true
	}
	// The repair rewrote catalog rows: the next tick compares against them.
	after, err := readTriggerIntegrity(ctx, c.ls.db, t)
	if err != nil || after.problem != "" {
		// The invalidation committed, but the state after it is not known
		// good: keep pending, so the next tick invalidates and re-reads again.
		return flushed, fmt.Errorf("%s triggers still not this release's after the repair: %q %v", t.what, after.problem, err)
	}
	c.baseline = after.version
	c.pending = false
	return flushed, nil
}

// StartTriggerIntegrityCheck runs the check of every target whose tables
// exist every rolePermGenerationIntegrityInterval in the background, the
// first one now. PostgreSQL only (a no-op on SQLite); Close stops it. A
// failed check is logged and retried at the next tick, never fatal: the
// per-statement proofs still fail closed for a missing or disabled trigger
// in the meantime.
func (ls *LocalStorage) StartTriggerIntegrityCheck(logf func(string, ...any)) {
	if ls.db.Dialector.Name() != "postgres" || ls.rolePermIntegrity != nil {
		return
	}
	var checkers []*triggerIntegrityChecker
	if storeTableExists(ls.db, "role_permissions") && storeTableExists(ls.db, "permissions") {
		checkers = append(checkers, &triggerIntegrityChecker{ls: ls, logf: logf, target: rolePermGenerationIntegrityTarget})
	}
	if secretNodesTableExists(ls.db) {
		checkers = append(checkers, &triggerIntegrityChecker{ls: ls, logf: logf, target: secretNodeCacheEpochIntegrityTarget})
	}
	if len(checkers) == 0 {
		return
	}
	ctx, job := newBackgroundJob()
	ls.rolePermIntegrity = job
	go func() {
		defer job.exit()
		tick := time.NewTicker(rolePermGenerationIntegrityInterval)
		defer tick.Stop()
		for {
			for _, c := range checkers {
				tctx, tcancel := context.WithTimeout(ctx, rolePermGenerationIntegrityTickTimeout)
				_, err := c.check(tctx)
				tcancel()
				if err != nil && ctx.Err() == nil {
					logf("%s trigger integrity check: %v", c.target.what, err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}
