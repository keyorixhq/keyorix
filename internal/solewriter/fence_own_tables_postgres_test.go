package solewriter

// fence_own_tables_postgres_test.go — the holder and epoch tables against a
// role that holds only table privileges (REVIEW-SINGLE-WRITER-3): N5, a write
// to the holder row itself must not open the fence; N6, a lock on the guard's
// own tables must not cost the guard its lock session; and the trigger census
// over every trigger on a covered table. pg-gated.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// privRole creates a NOSUPERUSER, non-owner role with privs on every table of
// the world's schema.
func (w *swWorld) privRole(tag, privs string) string {
	w.t.Helper()
	role := "swp" + tag + "_" + w.schema
	for _, s := range []string{
		"DROP ROLE IF EXISTS " + role,
		"CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
		// asRole's SET ROLE needs membership. A superuser has it implicitly;
		// a CREATEROLE role on PostgreSQL 16+ gets only ADMIN on a role it
		// creates (createrole_self_grant is empty by default), and SET ROLE
		// then fails with "permission denied to set role" (kpg, FENCE-VERIFY-1).
		"GRANT " + role + " TO CURRENT_USER",
		"GRANT USAGE ON SCHEMA " + w.schema + " TO " + role,
		"GRANT " + privs + " ON ALL TABLES IN SCHEMA " + w.schema + " TO " + role,
	} {
		require.NoError(w.t, w.foreign.Exec(s).Error, s)
	}
	w.t.Cleanup(func() {
		_ = w.foreign.Exec("DROP OWNED BY " + role).Error
		_ = w.foreign.Exec("DROP ROLE IF EXISTS " + role).Error
	})
	return role
}

// asRole runs stmts in one foreign transaction as role.
func (w *swWorld) asRole(role string, stmts ...string) error {
	return w.foreign.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL ROLE " + role).Error; err != nil {
			return err
		}
		for _, s := range stmts {
			if err := tx.Exec(s).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ownRows is every column and the row version of both own tables, as text.
func (w *swWorld) ownRows() string {
	w.t.Helper()
	var h, e sql.NullString
	require.NoError(w.t, w.foreign.Raw("SELECT (SELECT h::text || ':' || h.xmin::text FROM "+HolderTable+" h WHERE id = 1), (SELECT e::text || ':' || e.xmin::text FROM "+EpochTable+" e WHERE id = 1)").Row().Scan(&h, &e))
	return h.String + " | " + e.String
}

// TestFence_OwnTablesRefuseATablePrivilegedRole (REVIEW-SINGLE-WRITER-3 N5):
// a role with table privileges only writes every column of both own tables,
// deletes their rows, upserts and truncates them. Every write must be refused
// by the fence, leave both rows (values and row version) as they were, and
// leave the fence closed: the holder still holds the lock and a foreign write
// to a fenced table is still refused.
func TestFence_OwnTablesRefuseATablePrivilegedRole(t *testing.T) {
	h, e := HolderTable, EpochTable
	cases := map[string]string{
		"holder-id":                "UPDATE " + h + " SET id = id",
		"holder-holder_pid":        "UPDATE " + h + " SET holder_pid = pg_backend_pid()",
		"holder-holder_pid-null":   "UPDATE " + h + " SET holder_pid = NULL",
		"holder-nonce_hash":        "UPDATE " + h + " SET nonce_hash = encode(sha256(convert_to('', 'UTF8')), 'hex')",
		"holder-since":             "UPDATE " + h + " SET since = now()",
		"holder-boot_id":           "UPDATE " + h + " SET boot_id = 'x'",
		"holder-delete":            "DELETE FROM " + h,
		"holder-upsert":            "INSERT INTO " + h + " (id, holder_pid) VALUES (1, pg_backend_pid()) ON CONFLICT (id) DO UPDATE SET holder_pid = EXCLUDED.holder_pid",
		"holder-merge":             "MERGE INTO " + h + " t USING (SELECT 1 AS id) s ON t.id = s.id WHEN MATCHED THEN UPDATE SET holder_pid = NULL",
		"holder-truncate":          "TRUNCATE " + h,
		"holder-delete-then-write": "DELETE FROM " + h + "; UPDATE machine_identity_credentials SET revoked = true",
		"epoch-id":                 "UPDATE " + e + " SET id = id",
		"epoch-incarnation":        "UPDATE " + e + " SET incarnation = 'x'",
		"epoch-n":                  "UPDATE " + e + " SET n = n + 1",
		"epoch-delete":             "DELETE FROM " + e,
		"epoch-upsert":             "INSERT INTO " + e + " (id, incarnation, n) VALUES (1, 'x', 0) ON CONFLICT (id) DO UPDATE SET n = 0",
		"epoch-truncate":           "TRUNCATE " + e,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			role := w.privRole("o", "SELECT, INSERT, UPDATE, DELETE, TRUNCATE")
			before := w.ownRows()
			err := w.asRole(role, strings.Split(stmt, "; ")...)
			requireFenced(t, err, name)
			require.Equal(t, before, w.ownRows(), "%s: an own-table row changed", name)
			pid, err := holderPID(context.Background(), mustSQLConn(t, w), w.schema)
			require.NoError(t, err)
			require.Equal(t, g.PID(), pid)
			requireFenced(t, w.asRole(role, "UPDATE machine_identity_credentials SET revoked = true"), name+" then a fenced write")
			require.False(t, w.revoked())
			time.Sleep(2 * PollInterval)
			require.True(t, g.Authoritative(), "%s: a refused write must not cost the guard its state", name)
		})
	}
}

func mustSQLConn(t *testing.T, w *swWorld) *sql.DB {
	t.Helper()
	d, err := w.foreign.DB()
	require.NoError(t, err)
	return d
}

// TestPoll_HolderRowChangeLeavesAuthoritative (N5, second half): a session
// that passes the fence (here one carrying the holder's tag, as a copied tag
// would) rewrites the holder row. The poller compares holder_pid, nonce_hash
// and the row version with its own, so even a rewrite to the same values is
// seen.
func TestPoll_HolderRowChangeLeavesAuthoritative(t *testing.T) {
	for name, stmt := range map[string]string{
		"other-pid":   "UPDATE " + HolderTable + " SET holder_pid = holder_pid + 1",
		"other-hash":  "UPDATE " + HolderTable + " SET nonce_hash = 'x'",
		"same-values": "UPDATE " + HolderTable + " SET holder_pid = holder_pid, nonce_hash = nonce_hash",
		"deleted":     "DELETE FROM " + HolderTable,
	} {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			require.NoError(t, w.own().Exec(stmt).Error)
			d := waitFor(t, 2*time.Second, func() bool { return g.Status().State == StateConfirming })
			require.GreaterOrEqual(t, d, time.Duration(0), "the poller did not see the holder row change")
			require.Contains(t, g.Status().Reason, "holder row")
			time.Sleep(2 * PollInterval)
			require.False(t, g.Authoritative(), "a changed holder row leaves authoritative until restart")
		})
	}
}

// lockAs opens a foreign transaction as role and takes an ACCESS EXCLUSIVE
// lock on table. The lock is held until the returned transaction ends. An
// error here (a role that cannot SET ROLE or LOCK) fails the test with the
// database's text: a lock that was never taken must not read as a guard that
// stayed authoritative.
func (w *swWorld) lockAs(role, table string) *gorm.DB {
	w.t.Helper()
	tx := w.foreign.Begin()
	require.NoError(w.t, tx.Error)
	w.t.Cleanup(func() { tx.Rollback() })
	require.NoError(w.t, tx.Exec("SET LOCAL ROLE "+role).Error, "SET ROLE %s", role)
	require.NoError(w.t, tx.Exec("LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE").Error, "LOCK %s as %s", table, role)
	return tx
}

// pollOpens reports whether the poll statement needs a lock on table: it
// reads both own tables, and pg_get_triggerdef (fingerprintSQL) opens the
// table of a trigger with a WHEN clause (AccessShareLock) to deparse it.
func (w *swWorld) pollOpens(table string) bool {
	w.t.Helper()
	if table == HolderTable || table == EpochTable {
		return true
	}
	var when bool
	require.NoError(w.t, w.foreign.Raw(`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ? AND c.relname = ? AND NOT t.tgisinternal AND t.tgqual IS NOT NULL)`,
		w.schema, table).Scan(&when).Error)
	return when
}

// TestPoll_OwnTableLockKeepsTheHolderLock (REVIEW-SINGLE-WRITER-3 N6): a role
// with table privileges holds an ACCESS EXCLUSIVE lock on a covered table
// (coveredTableNames: every fenced table and both own tables) and, under that
// lock, tries to write it. Fail closed each time:
//   - the write is refused by the fence and changes no row, the epoch
//     included;
//   - when the poll needs a lock on the table (pollOpens), the poll blocks:
//     the lease runs out and is not renewed for as long as the lock is held
//     (a poll that renewed it without its answer would be a fail-open);
//   - otherwise polls keep succeeding during the lock;
//   - the lock never costs the guard its lock session: once it is released
//     the holder pid still holds the lock and the guard is authoritative.
//
// The lock is held until the test releases it, not for a fixed sleep, so a
// slow runner stretches the wait instead of racing the lock's end.
func TestPoll_OwnTableLockKeepsTheHolderLock(t *testing.T) {
	tables := coveredTableNames()
	require.Len(t, tables, len(FencedTables)+2)
	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
			role := w.privRole("l", "SELECT, INSERT, UPDATE, DELETE, TRUNCATE")
			before, epoch := w.ownRows(), w.epoch(w.foreign)
			blocks := w.pollOpens(table)
			t.Logf("%s: the poll needs a lock on it: %v", table, blocks)
			tx := w.lockAs(role, table)
			locked := time.Now()

			// A write under the lock: TRUNCATE fires the statement-level
			// guard whether or not the table has rows (CASCADE: some are
			// referenced by others). A savepoint keeps the lock.
			require.NoError(t, tx.SavePoint("w").Error)
			requireFenced(t, tx.Exec("TRUNCATE "+table+" CASCADE").Error, "TRUNCATE "+table+" under its lock")
			require.NoError(t, tx.RollbackTo("w").Error)

			if blocks {
				d := waitFor(t, 5*LeaseDuration, func() bool { return !g.Authoritative() })
				require.GreaterOrEqual(t, d, time.Duration(0), "a blocked poll must let the lease run out")
				// Every poll in this window blocks on the lock: none may renew
				// the lease.
				hold := time.Now().Add(3 * LeaseDuration)
				for time.Now().Before(hold) {
					require.False(t, g.Authoritative(), "the lease was renewed while %s was locked", table)
					time.Sleep(20 * time.Millisecond)
				}
				// The last good poll was sent before the lock was granted.
				elapsed := time.Since(locked).Milliseconds()
				st := g.Status()
				require.Equal(t, StateConfirming, st.State)
				require.Contains(t, st.Reason, "lease expired", "the lapse is the lease, not a permanent leave")
				require.NotEmpty(t, st.LastPollError, "the poll must have failed on the lock")
				require.GreaterOrEqual(t, st.LastPollAgeMS, elapsed, "a poll succeeded while %s was locked", table)
			} else {
				time.Sleep(3 * LeaseDuration)
				// A good poll was sent after the lock was granted.
				elapsed := time.Since(locked).Milliseconds()
				st := g.Status()
				require.Less(t, st.LastPollAgeMS, elapsed,
					"no poll succeeded during a lock on %s, which the poll does not need: state=%s reason=%q lastErr=%q", table, st.State, st.Reason, st.LastPollError)
			}

			require.NoError(t, tx.Rollback().Error)
			d := waitFor(t, 2*time.Second, g.Authoritative)
			st := g.Status()
			require.GreaterOrEqual(t, d, time.Duration(0), "not authoritative again after the lock cleared: state=%s reason=%q lastErr=%q", st.State, st.Reason, st.LastPollError)
			pid, err := holderPID(context.Background(), mustSQLConn(t, w), w.schema)
			require.NoError(t, err)
			require.Equal(t, g.PID(), pid, "the holder lost its lock session")
			require.Equal(t, before, w.ownRows(), "an own-table row changed")
			require.Equal(t, epoch, w.epoch(w.foreign), "the epoch moved")
			require.False(t, w.revoked())
		})
	}
}

// TestFence_ForeignTriggerOnACoveredTable (TRIGGER-privilege hardening): a
// trigger that is not one of the fence's on a covered table can rewrite or
// suppress rows around the fence. One present at install keeps the guard out
// of the authoritative state and is reported by InspectFence; one added later
// is a fingerprint change.
func TestFence_ForeignTriggerOnACoveredTable(t *testing.T) {
	fn := "CREATE FUNCTION sw_foreign_trg() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
	trg := "CREATE TRIGGER zz_foreign BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION sw_foreign_trg()"
	t.Run("at-install", func(t *testing.T) {
		w := newSWWorld(t)
		require.NoError(t, w.foreignTx(fn, trg))
		g := w.start(Options{})
		time.Sleep(2 * PollInterval)
		require.False(t, g.Authoritative())
		require.Equal(t, StateConfirming, g.Status().State)
		require.Contains(t, g.Status().Reason, "zz_foreign")
		rep, err := InspectFence(context.Background(), w.cfg)
		require.NoError(t, err)
		require.Equal(t, []string{"roles.zz_foreign"}, rep.ForeignTriggers)
	})
	t.Run("added-later", func(t *testing.T) {
		w := newSWWorld(t)
		g := w.start(Options{})
		require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
		require.NoError(t, w.foreignTx(fn, trg))
		d := waitFor(t, 2*time.Second, func() bool { return g.Status().State == StateConfirming })
		require.GreaterOrEqual(t, d, time.Duration(0))
		require.Contains(t, g.Status().Reason, "write fence changed")
	})
}

// TestInstallFence_RefusesAFenceTriggerThatDiffers: a trigger with a fence
// trigger's name, timing, events, level and function name, but another WHEN
// clause or a function of that name in another schema, is not the fence.
// InstallFence compares the full definition and refuses.
func TestInstallFence_RefusesAFenceTriggerThatDiffers(t *testing.T) {
	upd := TriggerPrefix + "guard_upd"
	cases := map[string][]string{
		"when-false": {
			"DROP TRIGGER " + upd + " ON machine_identity_credentials",
			"CREATE TRIGGER " + upd + " AFTER UPDATE ON machine_identity_credentials FOR EACH ROW WHEN (false) EXECUTE PROCEDURE " + guardFunc + "()",
		},
		"function-in-another-schema": {
			"CREATE SCHEMA %SCHEMA%_evil",
			"CREATE FUNCTION %SCHEMA%_evil." + guardFunc + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$",
			"DROP TRIGGER " + upd + " ON machine_identity_credentials",
			"CREATE TRIGGER " + upd + " AFTER UPDATE ON machine_identity_credentials FOR EACH ROW WHEN ((to_jsonb(OLD) - 'last_used_at') IS DISTINCT FROM (to_jsonb(NEW) - 'last_used_at')) EXECUTE PROCEDURE %SCHEMA%_evil." + guardFunc + "()",
		},
	}
	for name, stmts := range cases {
		t.Run(name, func(t *testing.T) {
			w := newSWWorld(t)
			g := w.start(Options{})
			g.Close()
			t.Cleanup(func() { _ = w.foreign.Exec("DROP SCHEMA IF EXISTS " + w.schema + "_evil CASCADE").Error })
			require.NoError(t, w.foreignTx(stmts...))
			g2, err := Start(context.Background(), w.cfg, Options{SkipPresenceCensus: true, LockWait: 500 * time.Millisecond})
			require.NoError(t, err)
			t.Cleanup(g2.Close)
			err = g2.InstallFence(context.Background())
			require.Error(t, err, "a differing fence trigger was accepted")
			require.Contains(t, err.Error(), "unexpected definition")
		})
	}
}
