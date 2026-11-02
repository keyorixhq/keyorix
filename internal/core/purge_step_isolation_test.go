// purge_step_isolation_test.go — PURGE-TX-TAILS-1 item 1: PurgeExpiredSoftDeletes
// documents a partial-success design (a failing step does not stop the others, and
// the result and the data.purged audit row report only what was removed), but the
// four steps share ONE outer transaction. On PostgreSQL a failed bare statement
// aborts that whole transaction: every later step fails with "current transaction is
// aborted", the closure still returns nil, and the COMMIT is downgraded to a
// ROLLBACK — while PurgeResult and the audit row still counted the rows of the steps
// that "succeeded" before the failure.
//
// The fault is a real statement failure (a BEFORE DELETE trigger that raises on
// environments), not a faultstorage double: a double never reaches the database and
// cannot poison a transaction. Each test runs on SQLite and, when
// KEYORIX_TEST_PG_DSN is set, on PostgreSQL, and asserts the effect: what the
// database holds against what PurgeResult and the audit row claim.
package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// purgeBackend is one database the isolation tests run against.
type purgeBackend struct {
	name string
	open func(t *testing.T) *gorm.DB
	// failDelete makes every DELETE on table fail with a real statement error.
	failDelete func(t *testing.T, db *gorm.DB, table string)
}

func purgeBackends() []purgeBackend {
	return []purgeBackend{
		{
			name: "sqlite",
			open: func(t *testing.T) *gorm.DB {
				db := sqlitetest.OpenWithDialector(t, "purgestepisolation_", sqlite.Open, &gorm.Config{})
				require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
				return db
			},
			failDelete: func(t *testing.T, db *gorm.DB, table string) {
				require.NoError(t, db.Exec(fmt.Sprintf(
					"CREATE TRIGGER force_%[1]s_delete_fail BEFORE DELETE ON %[1]s BEGIN SELECT RAISE(ABORT, 'forced %[1]s delete failure'); END",
					table)).Error)
			},
		},
		{
			name: "postgres",
			open: func(t *testing.T) *gorm.DB {
				dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
				db := pgOpen(t, dsn)
				require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
				return db
			},
			failDelete: func(t *testing.T, db *gorm.DB, table string) {
				require.NoError(t, db.Exec(fmt.Sprintf(
					"CREATE FUNCTION force_%[1]s_delete_fail() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced %[1]s delete failure'; END $$ LANGUAGE plpgsql",
					table)).Error)
				require.NoError(t, db.Exec(fmt.Sprintf(
					"CREATE TRIGGER force_%[1]s_delete_fail BEFORE DELETE ON %[1]s FOR EACH ROW EXECUTE FUNCTION force_%[1]s_delete_fail()",
					table)).Error)
			},
		},
	}
}

// purgeFixture holds one expired row of each entity type.
type purgeFixture struct {
	user, project, env, secret uint
}

func seedExpiredOfEveryType(t *testing.T, db *gorm.DB, expired time.Time) purgeFixture {
	t.Helper()
	u := &models.User{Username: "u-exp", UsernameFolded: "u-exp", EmailFolded: "u-exp@example.com"}
	require.NoError(t, db.Create(u).Error)
	pLive := &models.Project{Name: "p-live"}
	require.NoError(t, db.Create(pLive).Error)
	eLive := &models.Environment{ProjectID: pLive.ID, Name: "e-live"}
	require.NoError(t, db.Create(eLive).Error)
	pExp := &models.Project{Name: "p-exp"}
	require.NoError(t, db.Create(pExp).Error)
	eExp := &models.Environment{ProjectID: pLive.ID, Name: "e-exp"}
	require.NoError(t, db.Create(eExp).Error)
	s := &models.SecretNode{ProjectID: pLive.ID, EnvironmentID: eLive.ID, Name: "s-exp"}
	require.NoError(t, db.Create(s).Error)

	softDelete(t, db, "users", u.ID, expired)
	softDelete(t, db, "projects", pExp.ID, expired)
	softDelete(t, db, "environments", eExp.ID, expired)
	softDelete(t, db, "secret_nodes", s.ID, expired)
	return purgeFixture{user: u.ID, project: pExp.ID, env: eExp.ID, secret: s.ID}
}

// purgeAuditClaim returns the data.purged descriptions currently in audit_events.
func purgeAuditClaims(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var descs []string
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "data.purged").Order("id").Pluck("description", &descs).Error)
	return descs
}

// TestPurgeExpiredSoftDeletes_FailingMiddleStepDoesNotPoisonTheRest: the environments
// delete fails for real; users, projects and secrets must still be purged AND stay
// purged (the transaction committed), the environments step reports 0 for itself, and
// the audit row claims exactly what the database lost.
func TestPurgeExpiredSoftDeletes_FailingMiddleStepDoesNotPoisonTheRest(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	for _, be := range purgeBackends() {
		t.Run(be.name, func(t *testing.T) {
			t.Parallel()
			db := be.open(t)
			c := NewKeyorixCore(store.NewLocalStorage(db))
			now := time.Now().UTC()
			fx := seedExpiredOfEveryType(t, db, now.AddDate(0, 0, -60))
			be.failDelete(t, db, "environments")

			res, err := c.PurgeExpiredSoftDeletes(context.Background(), now.AddDate(0, 0, -30))

			// Effect first: what the database holds.
			held := map[string]bool{
				"users":        rowExists(t, db, "users", fx.user),
				"projects":     rowExists(t, db, "projects", fx.project),
				"environments": rowExists(t, db, "environments", fx.env),
				"secret_nodes": rowExists(t, db, "secret_nodes", fx.secret),
			}
			claims := purgeAuditClaims(t, db)
			t.Logf("backend=%s err=%v result=%+v rowsStillPresent=%v auditClaims=%q", be.name, err, res, held, claims)

			require.Error(t, err, "the failing step's error is reported")
			require.NotNil(t, res)

			assert.False(t, held["users"], "users step must commit")
			assert.False(t, held["projects"], "projects step must commit")
			assert.False(t, held["secret_nodes"], "secrets step must commit")
			assert.True(t, held["environments"], "the failed environments delete removed nothing")

			assert.Equal(t, int64(1), res.Users)
			assert.Equal(t, int64(1), res.Projects)
			assert.Equal(t, int64(0), res.Environments, "a failing step reports 0 rows for itself")
			assert.Equal(t, int64(1), res.Secrets)

			require.Len(t, claims, 1, "rows were removed, so exactly one data.purged event")
			assert.Contains(t, claims[0], "removed 3 soft-deleted records")
			assert.Contains(t, claims[0], "environments=0")
		})
	}
}

// TestPurgeExpiredSoftDeletes_AllStepsFailingClaimsNothing: when every step's delete
// fails, nothing is purged, the result is all zero and no data.purged row is written.
func TestPurgeExpiredSoftDeletes_AllStepsFailingClaimsNothing(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	for _, be := range purgeBackends() {
		t.Run(be.name, func(t *testing.T) {
			t.Parallel()
			db := be.open(t)
			c := NewKeyorixCore(store.NewLocalStorage(db))
			now := time.Now().UTC()
			fx := seedExpiredOfEveryType(t, db, now.AddDate(0, 0, -60))
			for _, table := range []string{"users", "projects", "environments", "secret_nodes"} {
				be.failDelete(t, db, table)
			}

			res, err := c.PurgeExpiredSoftDeletes(context.Background(), now.AddDate(0, 0, -30))
			require.Error(t, err)
			require.NotNil(t, res)
			assert.Equal(t, PurgeResult{}, *res)
			assert.True(t, rowExists(t, db, "users", fx.user))
			assert.True(t, rowExists(t, db, "projects", fx.project))
			assert.True(t, rowExists(t, db, "environments", fx.env))
			assert.True(t, rowExists(t, db, "secret_nodes", fx.secret))
			assert.Empty(t, purgeAuditClaims(t, db), "nothing was purged, so no data.purged claim")
			assert.False(t, strings.Contains(err.Error(), "current transaction is aborted"),
				"each step fails for its own reason, not because an earlier one aborted the transaction: %v", err)
		})
	}
}
