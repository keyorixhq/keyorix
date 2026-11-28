// hostzone_model_stamps_test.go -- HOSTZONE-TIME-NOV-1 item 1, internal/core half.
//
// Core stamps a persisted model's CreatedAt / UpdatedAt with time.Now() (host zone). GORM's NowFunc
// is UTC but stamps only a ZERO field, so an explicit host-zone value is stored as given: on SQLite
// as text carrying the host offset ("... +0900 JST"), which SQLite compares by wall clock and so does
// not order against the UTC values every other writer stores; on PostgreSQL (timestamptz) it is an
// instant and harmless.
//
// Each test drives one site through the real core entry point on a TZ=Asia/Tokyo host (the child
// process of forEachUTCDialect; time.Local is never assigned) and reads the stored column back:
//   - SQLite: the text must be the UTC form and inside the window the call ran in, and a SQL
//     predicate `col <= <UTC bound>` must find the row (a host-zone text sorts 9 hours late);
//   - PostgreSQL (KEYORIX_TEST_PG_DSN): the same window and predicate on the instant.
//
// Two groups, named so a reviewer can see the classification:
//   - TestHostZoneStamps_CoreWritesStoreUTC: the sites that were real defects (red on main);
//   - TestHostZoneStamps_CoreHarmlessSitesStayUTC: sites that keep a host-zone stamp in memory but
//     whose store normalises it on the way in. They are left as they are and pinned here, so a store
//     change that stopped normalising turns them red instead of silently corrupting the column.

package core

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// storedTextLayout is how modernc writes a time.Time: "2006-01-02 15:04:05.999999999 -0700 MST".
const storedTextLayout = "2006-01-02 15:04:05.999999999 -0700 MST"

func tableOf(t *testing.T, db *gorm.DB, model any) string {
	t.Helper()
	stmt := &gorm.Statement{DB: db}
	require.NoError(t, stmt.Parse(model))
	return stmt.Schema.Table
}

// requireStoredNow asserts one column holds a time inside [before, after], in UTC on SQLite, and
// that a predicate against a UTC bound agrees (the comparison a host-zone text gets wrong).
func (d utcDialect) requireStoredNow(t *testing.T, db *gorm.DB, table, column string, before, after time.Time, where string, args ...any) {
	t.Helper()
	var stored time.Time
	if d.pg {
		var got *time.Time
		require.NoError(t, db.Table(table).Select(column).Where(where, args...).Scan(&got).Error)
		require.NotNil(t, got, "%s.%s is NULL (where %s)", table, column, where)
		stored = *got
	} else {
		var s *string
		require.NoError(t, db.Raw("SELECT CAST("+column+" AS TEXT) FROM "+table+" WHERE "+where, args...).Scan(&s).Error)
		require.NotNil(t, s, "%s.%s is NULL (where %s)", table, column, where)
		require.NotContains(t, *s, hostZoneOffset, "%s.%s stored with the host offset: %q (want UTC)", table, column, *s)
		require.Regexp(t, ` \+0000 UTC$`, *s, "%s.%s stored %q, not the UTC form", table, column, *s)
		var err error
		stored, err = time.Parse(storedTextLayout, *s)
		require.NoError(t, err, "%s.%s stored unparseable text %q", table, column, *s)
	}
	require.False(t, stored.Before(before) || stored.After(after), "%s.%s = %s, want a time in [%s, %s]", table, column, stored.UTC(), before.UTC(), after.UTC())

	// A row written "now" is at or before a bound an hour ahead, whatever the host zone.
	var n int64
	bound := after.Add(time.Hour).UTC()
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM "+table+" WHERE ("+where+") AND "+column+" <= ?", append(args, bound)...).Scan(&n).Error)
	require.EqualValues(t, 1, n, "%s.%s <= %s did not find the row just written", table, column, bound)
}

func stampWindow() (before, after time.Time) {
	return time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Minute)
}

func hostZoneCore(db *gorm.DB) *KeyorixCore {
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
}

func seedProjectEnv(t *testing.T, c *KeyorixCore) (*models.Project, *models.Environment) {
	t.Helper()
	ctx := context.Background()
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "hz-" + t.Name()})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	return p, e
}

var hostZoneCoreTables = []any{
	&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	&models.AuditEvent{}, &models.SecretTemplate{}, &models.AnomalyConfigRecord{}, &models.SecretAccessSchedule{},
	&models.SecretAccessLog{},
}

func TestHostZoneStamps_CoreWritesStoreUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, hostZoneCoreTables...)
		c := hostZoneCore(db)
		ctx := context.Background()
		p, e := seedProjectEnv(t, c)

		t.Run("CreateSecret", func(t *testing.T) {
			before, after := stampWindow()
			s, err := c.CreateSecret(ctx, &CreateSecretRequest{
				Name: "hz-secret", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
				Type: "password", CreatedBy: "owner", OwnerID: 1,
			})
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_nodes", "created_at", before, after, "id = ?", s.ID)
			d.requireStoredNow(t, db, "secret_nodes", "updated_at", before, after, "id = ?", s.ID)
		})

		t.Run("CreateFolder", func(t *testing.T) {
			before, after := stampWindow()
			f, err := c.CreateFolder(ctx, 1, "hz-folder", p.ID, e.ID, nil)
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_nodes", "created_at", before, after, "id = ?", f.ID)
			d.requireStoredNow(t, db, "secret_nodes", "updated_at", before, after, "id = ?", f.ID)
		})

		t.Run("CreateSecretTemplate", func(t *testing.T) {
			before, after := stampWindow()
			tpl, err := c.CreateSecretTemplate(ctx, &CreateSecretTemplateRequest{Name: "hz-template", CreatedBy: 1})
			require.NoError(t, err)
			table := tableOf(t, db, &models.SecretTemplate{})
			d.requireStoredNow(t, db, table, "created_at", before, after, "id = ?", tpl.ID)
			d.requireStoredNow(t, db, table, "updated_at", before, after, "id = ?", tpl.ID)
		})

		// storeSecretVersion stamped CreatedAt with time.Now(): secret_versions.created_at was stored
		// "... +0900 JST" on a Tokyo host.
		t.Run("CreateSecret stores the version row's created_at in UTC", func(t *testing.T) {
			before, after := stampWindow()
			s, err := c.CreateSecret(ctx, &CreateSecretRequest{
				Name: "hz-version", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
				Type: "password", CreatedBy: "owner", OwnerID: 1,
			})
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_versions", "created_at", before, after, "secret_node_id = ?", s.ID)
		})

	})
}

func TestHostZoneStamps_CoreHarmlessSitesStayUTC(t *testing.T) {
	forEachUTCDialect(t, func(t *testing.T, d utcDialect) {
		setNonUTCHostZone(t)
		db := d.open(t, hostZoneCoreTables...)
		c := hostZoneCore(db)
		ctx := context.Background()
		p, e := seedProjectEnv(t, c)

		// Seeded straight through the store with UTC stamps, so a failure below is the update's own.
		seed := func(name string) *models.SecretNode {
			now := time.Now().UTC().Add(-time.Hour)
			s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: name, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1, IsSecret: true,
				Status: SecretStatusActive, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
			return s
		}

		// SaveAnomalyConfig is Save(struct): gorm's UPDATE stamps updated_at from NowFunc over the
		// caller's value and writes it back into the struct, so the conflict-insert fallback (no row
		// yet, the case driven here) stores UTC too.
		t.Run("UpdateAnomalyConfig goes through Save(struct), which restamps updated_at from NowFunc", func(t *testing.T) {
			before, after := stampWindow()
			cfg := &models.AnomalyConfigRecord{
				LookbackDays: 7, QuarantineHours: 24, OffHoursTimezone: "UTC", OffHoursStart: 22, OffHoursEnd: 6,
				MLThreshold: 0.6, MLNumTrees: 100, MLSampleSize: 256,
			}
			require.NoError(t, c.UpdateAnomalyConfig(ctx, cfg, "owner", 1))
			d.requireStoredNow(t, db, tableOf(t, db, &models.AnomalyConfigRecord{}), "updated_at", before, after, "id = ?", 1)
		})

		t.Run("UpdateSecret goes through UpdateSecretFields, which stores updated_at UTC", func(t *testing.T) {
			s := seed("hz-update")
			before, after := stampWindow()
			_, err := c.UpdateSecret(ctx, &UpdateSecretRequest{ID: s.ID, Type: "api_key", UpdatedBy: "owner"})
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_nodes", "updated_at", before, after, "id = ?", s.ID)
		})

		t.Run("RotateSecret goes through UpdateSecretFields, which stores updated_at and last_rotated_at UTC", func(t *testing.T) {
			s := seed("hz-rotate")
			before, after := stampWindow()
			_, err := c.RotateSecret(ctx, s.ID, []byte("rotated-value-1"), 1, "owner")
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_nodes", "updated_at", before, after, "id = ?", s.ID)
			d.requireStoredNow(t, db, "secret_nodes", "last_rotated_at", before, after, "id = ?", s.ID)
		})

		t.Run("UpdateSecretTemplate goes through UpdateSecretTemplateFields, which stores updated_at UTC", func(t *testing.T) {
			tpl, err := c.CreateSecretTemplate(ctx, &CreateSecretTemplateRequest{Name: "hz-template-upd", CreatedBy: 1})
			require.NoError(t, err)
			before, after := stampWindow()
			_, err = c.UpdateSecretTemplate(ctx, tpl.ID, &UpdateSecretTemplateRequest{Name: "hz-template-upd", Description: "changed"})
			require.NoError(t, err)
			d.requireStoredNow(t, db, tableOf(t, db, &models.SecretTemplate{}), "updated_at", before, after, "id = ?", tpl.ID)
		})
	})
}

// TestHostZoneStamps_SecretVersionCreatedAtAnyHostZone runs in whatever zone the test binary was
// started in (no subprocess), so `TZ=Pacific/Auckland go test -run ...` proves a second non-UTC zone
// (+1200/+1300, the opposite side of the date line from Tokyo). On a UTC host it is a plain UTC check.
func TestHostZoneStamps_SecretVersionCreatedAtAnyHostZone(t *testing.T) {
	for _, d := range []utcDialect{{name: "sqlite"}, {name: "postgres", pg: true}} {
		t.Run(d.name, func(t *testing.T) {
			if d.pg && os.Getenv("KEYORIX_TEST_PG_DSN") == "" {
				t.Skip("KEYORIX_TEST_PG_DSN not set — skipping the PostgreSQL half of this UTC-write test")
			}
			db := d.open(t, hostZoneCoreTables...)
			c := hostZoneCore(db)
			p, e := seedProjectEnv(t, c)
			before, after := stampWindow()
			s, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
				Name: "hz-version-any", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
				Type: "password", CreatedBy: "owner", OwnerID: 1,
			})
			require.NoError(t, err)
			d.requireStoredNow(t, db, "secret_versions", "created_at", before, after, "secret_node_id = ?", s.ID)
		})
	}
}
