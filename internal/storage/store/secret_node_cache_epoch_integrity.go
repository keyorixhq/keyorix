// secret_node_cache_epoch_integrity.go — the periodic check that the
// secret_nodes cache-epoch trigger and its function are still the ones this
// binary installed (TRIGGER-HARDEN-1, the follow-up named in
// docs/design/trigger-rowdigest.md). Same attacker, same method and same
// limits as role_permission_generation_integrity.go; read that header first.
//
// The per-read proof (SecretNodeCacheEpochTriggerPresent) shows that
// trg_secret_nodes_cache_epoch exists and is ENABLE ALWAYS. It does not show
// what it runs. The owner of the function (the server's own database role) can
// replace its body with one that stamps nothing, ALTER FUNCTION ... SET
// search_path, or re-create the trigger as AFTER or with a WHEN clause, and
// every update made directly in SQL afterwards leaves the row's cache_epoch
// where it was: every warm replica keeps serving the old row from its node
// cache.
//
// Every tick reads, in one catalog statement, the trigger's definition (BEFORE
// UPDATE FOR EACH ROW, ENABLE ALWAYS), the function it calls (body, language,
// pinned search_path as the exact proconfig, not SECURITY DEFINER), and the
// row versions (tgfoid and xmin of the pg_trigger and pg_proc rows). The body
// is compared as the text pg_proc stores, which is stronger than comparing a
// hash of it. A bad definition, or a changed row version with a good
// definition, is handled as the role-permission check handles it: log, count,
// invalidate (here: bump cache_epoch of every secret_nodes row, in a
// transaction of its own), restore (EnsureSecretNodeCacheEpoch under a
// lock_timeout) and bump again. A failed repair stays pending and every tick
// bumps again until a repair commits and the re-read is clean.
//
// The bump is a table-wide UPDATE of one column, so on a large secret_nodes it
// is not free; it runs only on a detected change, and again on every tick while
// a repair keeps failing. If the replaced body skips the row (RETURN NULL) or
// the table is locked, the first bump may not land; the second one, after the
// restore, does.
//
// Limits, stated: one interval (plus one tick timeout) between the change and
// the flush, for deliberate DDL by the owner or a superuser only (a missing,
// disabled or ordinary-mode trigger keeps the per-read proof's zero window);
// a superuser below SQL is not detected; the check covers the trigger and
// function, not the cache_epoch column (a BEFORE UPDATE trigger of another name
// that overwrites it, a revoked column privilege, a rule); PostgreSQL only.
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/gorm"
)

var secretNodeCacheEpochTamperTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_secret_node_cache_epoch_tamper_total",
	Help: "Times the secret_nodes cache-epoch trigger or its function were found changed (replaced function, altered settings, re-created or re-enabled trigger) and every replica's secret metadata cache was invalidated.",
})

// secretNodeCacheEpochIntegritySQL reads the one trigger's enabled state,
// whether its definition and its function are this binary's, and its row
// versions. One bind: the expected function body.
const secretNodeCacheEpochIntegritySQL = `SELECT t.tgname AS name, t.tgenabled::text AS state,
  (` + pgSecretNodeCacheEpochTriggerDefOK + `) AS def_ok,
  COALESCE(` + pgSecretNodeCacheEpochFuncOK + ` AND p.pronamespace = c.relnamespace, false) AS func_ok,
  t.tgfoid::text || ':' || t.xmin::text || ':' || COALESCE(p.xmin::text, '-') AS version
FROM pg_catalog.pg_trigger t
JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
LEFT JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE NOT t.tgisinternal AND t.tgrelid = 'secret_nodes'::regclass AND t.tgname = '` + SecretNodeCacheEpochTrigger + `'`

// secretNodeCacheEpochIntegrityRawSQL is the same statement with a native $1
// bind, for the read that goes around GORM (see
// readRolePermGenerationIntegrity for why).
var secretNodeCacheEpochIntegrityRawSQL = strings.Replace(secretNodeCacheEpochIntegritySQL, "?", "$1", 1)

// secretNodeCacheEpochIntegrityState is one reading: problem is "" when the
// definition is this binary's, version the row versions.
type secretNodeCacheEpochIntegrityState struct {
	problem string
	version string
}

func readSecretNodeCacheEpochIntegrity(ctx context.Context, db *gorm.DB) (secretNodeCacheEpochIntegrityState, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return secretNodeCacheEpochIntegrityState{}, err
	}
	rs, err := sqlDB.QueryContext(ctx, secretNodeCacheEpochIntegrityRawSQL, postgresSecretNodeCacheEpochFuncBody)
	if err != nil {
		return secretNodeCacheEpochIntegrityState{}, err
	}
	defer func() { _ = rs.Close() }()
	var st secretNodeCacheEpochIntegrityState
	n := 0
	for rs.Next() {
		var name, state, version string
		var defOK, funcOK bool
		if err := rs.Scan(&name, &state, &defOK, &funcOK, &version); err != nil {
			return secretNodeCacheEpochIntegrityState{}, err
		}
		n++
		st.version = name + "=" + version
		switch {
		case state != "A":
			st.problem = fmt.Sprintf("%s is not ENABLE ALWAYS (tgenabled %q)", name, state)
		case !defOK:
			st.problem = name + " was re-created with a different definition"
		case !funcOK:
			st.problem = name + " calls a function that is not this release's " + secretNodeCacheEpochFunc + "()"
		}
	}
	if err := rs.Err(); err != nil {
		return secretNodeCacheEpochIntegrityState{}, err
	}
	if n == 0 {
		st.problem = SecretNodeCacheEpochTrigger + " is missing"
	}
	return st, nil
}

// bumpAllSecretNodeCacheEpochsTx moves the stamp of every secret_nodes row, so
// every replica's cached node re-reads from the database. The column is
// written explicitly because a replaced function does not move it; the correct
// function overwrites it with OLD+1 either way.
func bumpAllSecretNodeCacheEpochsTx(tx *gorm.DB) error {
	return tx.Exec("UPDATE secret_nodes SET " + SecretNodeCacheEpochColumn + " = " + SecretNodeCacheEpochColumn + " + 1").Error
}

// secretNodeCacheEpochIntegrityChecker holds the last good reading of one
// store's database. Its pending/baseline rules are the role-permission
// checker's (see rolePermGenerationIntegrityChecker).
type secretNodeCacheEpochIntegrityChecker struct {
	ls       *LocalStorage
	logf     func(string, ...any)
	baseline string
	pending  bool
}

// check runs one tick and reports whether it invalidated the caches. The first
// tick records the baseline (and repairs a bad definition like any other tick).
func (c *secretNodeCacheEpochIntegrityChecker) check(ctx context.Context) (bool, error) {
	st, err := readSecretNodeCacheEpochIntegrity(ctx, c.ls.db)
	if err != nil {
		return false, fmt.Errorf("read the secret_nodes cache-epoch trigger: %w", err)
	}
	switch {
	case st.problem != "":
		c.logf("SECURITY: secret_nodes cache-epoch trigger changed outside this server: %s. Restoring it and invalidating every replica's secret metadata cache; find who has DDL on this schema.", st.problem)
	case c.pending:
		c.logf("SECURITY: retrying the secret_nodes cache invalidation after a failed attempt (catalog row versions %s, last good %s).", st.version, c.baseline)
	case c.baseline == "" || st.version == c.baseline:
		c.baseline = st.version
		return false, nil
	default:
		c.logf("SECURITY: secret_nodes cache-epoch trigger or function rewritten outside this server (catalog row versions %s, were %s), now matching this release again. Invalidating every replica's secret metadata cache; find who has DDL on this schema.", st.version, c.baseline)
	}
	secretNodeCacheEpochTamperTotal.Inc()
	c.pending = true
	// The bump commits on its own first: invalidation never waits on, or rolls
	// back with, a repair that cannot finish.
	if err := c.ls.db.WithContext(ctx).Transaction(bumpAllSecretNodeCacheEpochsTx); err != nil {
		return false, fmt.Errorf("invalidate the secret_nodes caches: %w", err)
	}
	if st.problem != "" {
		// The repair bumps again in its own transaction, once the restored
		// trigger is in place. lock_timeout: its DROP TRIGGER takes an ACCESS
		// EXCLUSIVE lock on secret_nodes.
		if err := c.ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", rolePermGenerationRepairLockTimeout.Milliseconds())).Error; err != nil {
				return err
			}
			if err := ensurePostgresCacheEpochTrigger(tx); err != nil {
				return err
			}
			return bumpAllSecretNodeCacheEpochsTx(tx)
		}); err != nil {
			return true, fmt.Errorf("restore the secret_nodes cache-epoch trigger: %w", err)
		}
	}
	after, err := readSecretNodeCacheEpochIntegrity(ctx, c.ls.db)
	if err != nil || after.problem != "" {
		return true, fmt.Errorf("secret_nodes cache-epoch trigger still not this release's after the repair: %q %v", after.problem, err)
	}
	c.baseline = after.version
	c.pending = false
	return true, nil
}
