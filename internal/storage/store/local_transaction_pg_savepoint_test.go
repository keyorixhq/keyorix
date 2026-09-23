// local_transaction_pg_savepoint_test.go — PostgreSQL-only: proves gorm's
// nested Transaction() call (what storage.Storage.WithTransaction calls into,
// see local_transaction.go) genuinely uses a SAVEPOINT when called from
// WITHIN an already-open transaction, containing a real statement failure to
// just that nested scope instead of poisoning the whole outer transaction.
//
// This matters because SQLite has no equivalent "transaction is aborted,
// commands ignored until end of transaction block" behavior — a failed
// statement there just fails, leaving the transaction otherwise usable. On
// PostgreSQL, ANY failed statement inside a transaction poisons it at the
// protocol level: every later statement errors, and COMMIT itself downgrades
// to ROLLBACK (pgx's ErrTxCommitRollback). internal/core's CreateProject/
// CreateProjectWithEnvs/CreateUser each have a step that's INTENTIONALLY
// non-fatal (env seeding, the baseline system_viewer role grant) — without
// wrapping that step in its own nested tx.WithTransaction (a SAVEPOINT), a
// single faulted non-fatal step would silently fail the WHOLE surrounding
// create on PostgreSQL, defeating the entire point of it being "non-fatal."
// docs/findings/2026-09-23-FINDING-create-ops-ambiguous-commit-mixed-state.md's
// "PostgreSQL validation" section has the full writeup.
//
// Uses a genuinely failing raw SQL statement (a syntax error), not
// faultstorage's synthetic fault injection: faultstorage's KindError never
// reaches the database at all, and KindEffectThenError's real call genuinely
// SUCCEEDS (only the Go-level response to the caller is faked) — neither
// produces the real "a statement actually failed" condition this test needs.
package store

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func newPGTxStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	schema := "txsavepoint_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return NewLocalStorage(db)
}

// TestPGTransaction_UnprotectedStatementFailure_PoisonsWholeTransaction is the
// RED case: a genuinely failing statement inside the outer transaction, run
// WITHOUT a nested SAVEPOINT, aborts the whole transaction on PostgreSQL —
// even though the caller's own Go code tries to treat the failure as
// non-fatal (swallows the error, returns nil). The outer WithTransaction call
// itself still fails, and the "unrelated, otherwise-successful" write made
// earlier in the same transaction is rolled back too. This is the exact
// PostgreSQL-specific failure mode #1996's review comment described.
func TestPGTransaction_UnprotectedStatementFailure_PoisonsWholeTransaction(t *testing.T) {
	ls := newPGTxStore(t)
	ctx := context.Background()

	err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		txls := tx.(*LocalStorage)
		// A real, unrelated, otherwise-successful write earlier in the transaction.
		if _, err := txls.CreateProject(ctx, &models.Project{Name: "unprotected-case"}); err != nil {
			return err
		}
		// A genuinely failing statement, run directly (no SAVEPOINT) — exactly
		// how CreateEnvironment's bare `ls.db.Create(env).Error` would behave
		// if a real constraint violation or driver error hit it.
		if execErr := txls.db.WithContext(ctx).Exec("SELECT this is not valid sql").Error; execErr != nil {
			// Caller treats this as non-fatal: log-and-continue, do NOT return the error.
			t.Logf("non-fatal step failed as expected: %v", execErr)
		}
		return nil // caller believes the transaction can still commit cleanly
	})
	require.Error(t, err, "PostgreSQL must fail the whole transaction — the poisoned state survives to COMMIT")

	// Confirm the "unrelated, otherwise-successful" write was ALSO rolled back —
	// the exact "everything fails" symptom, not just the non-fatal step itself.
	var count int64
	require.NoError(t, ls.db.Model(&models.Project{}).Where("name = ?", "unprotected-case").Count(&count).Error)
	require.Zero(t, count, "the unrelated write must be gone too — the whole transaction was poisoned, not just the failed statement")
}

// TestPGTransaction_SavepointProtectedFailure_DoesNotPoisonOuterTransaction is
// the GREEN case: the identical genuine statement failure, this time wrapped
// in its own nested tx.WithTransaction (a SAVEPOINT), does NOT poison the
// outer transaction — the earlier, unrelated write commits successfully, and
// the WithTransaction call itself succeeds. This proves the SAVEPOINT
// mechanism CreateProject/CreateProjectWithEnvs/CreateUser's non-fatal steps
// now use (see catalog.go/users.go) genuinely contains a real PostgreSQL
// statement failure — not just faultstorage's synthetic fault, which cannot
// reproduce this condition at all (see the package doc comment above).
func TestPGTransaction_SavepointProtectedFailure_DoesNotPoisonOuterTransaction(t *testing.T) {
	ls := newPGTxStore(t)
	ctx := context.Background()

	err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, err := tx.CreateProject(ctx, &models.Project{Name: "savepoint-protected-case"}); err != nil {
			return err
		}
		// Same genuine failure, this time inside a nested WithTransaction —
		// gorm's Transaction() detects the already-open outer transaction and
		// uses a SAVEPOINT instead of BEGIN, so ROLLBACK TO SAVEPOINT contains
		// the damage instead of aborting the whole session.
		if spErr := tx.WithTransaction(ctx, func(savepoint storage.Storage) error {
			return savepoint.(*LocalStorage).db.WithContext(ctx).Exec("SELECT this is not valid sql").Error
		}); spErr != nil {
			t.Logf("non-fatal step failed as expected, contained by the savepoint: %v", spErr)
		}
		return nil
	})
	require.NoError(t, err, "the outer transaction must still commit — the savepoint contained the real failure")

	var count int64
	require.NoError(t, ls.db.Model(&models.Project{}).Where("name = ?", "savepoint-protected-case").Count(&count).Error)
	require.Equal(t, int64(1), count, "the unrelated write must have survived — the savepoint isolated the failure to just the nested step")
}
