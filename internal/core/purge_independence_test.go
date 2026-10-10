// purge_independence_test.go — INV-CORE-29 (#2497): ADR-032 "Decision" says
// each soft-deleted top-level entity (user/project/environment/secret) is
// purged independently on its OWN deleted_at -- "no cascade logic in the
// purge (a soft-deleted project's environments carry their own deleted_at
// and are purged by their own query)".
//
// purge_test.go's four separate Purge*Before mock expectations only imply
// this: a mock cannot see a cascade implemented inside the storage layer
// (e.g. PurgeDeletedProjectsBefore also hard-deleting its environments), and
// it cannot see a purge that keys a child off its parent's deleted_at. This
// test runs PurgeExpiredSoftDeletes against real LocalStorage and asserts the
// effect in both directions:
//
//   - down: an EXPIRED parent's children that are live, or soft-deleted but
//     still inside the retention window, survive the parent's purge;
//   - up:   EXPIRED children of a parent that is live, or soft-deleted but
//     still inside the window, are purged while the parent survives.
//
// What this does NOT cover: the deliberate child-row cleanup ADR-032's
// independence rule does not apply to -- rows with no deleted_at of their
// own (secret versions, dependency edges, ACLs, role grants, sessions, PATs)
// ARE removed with their owner by design, and are asserted by the
// TestPurgeDeleted*_Cascades* tests in internal/storage/store/local_purge_test.go.
// Per-secret retention overrides are covered by
// TestPurgeDeletedSecretsBefore_RespectsRetentionOverride.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func newPurgeIndependenceCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "purgeindependence_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// softDelete stamps deleted_at directly (bypassing the core soft-delete paths,
// which cascade soft-deletes and would make every fixture state below
// unreachable) so each row's age can be set independently of its parent's.
func softDelete(t *testing.T, db *gorm.DB, table string, id uint, at time.Time) {
	t.Helper()
	require.NoError(t, db.Exec("UPDATE "+table+" SET deleted_at = ? WHERE id = ?", at, id).Error)
}

func rowExists(t *testing.T, db *gorm.DB, table string, id uint) bool {
	t.Helper()
	var n int64
	require.NoError(t, db.Table(table).Where("id = ?", id).Count(&n).Error) // raw Table: sees soft-deleted rows too
	return n == 1
}

func TestPurgeExpiredSoftDeletes_EntitiesPurgedIndependently(t *testing.T) {
	t.Parallel()
	c, db := newPurgeIndependenceCore(t)

	now := time.Now().UTC()
	before := now.AddDate(0, 0, -30) // retention cutoff
	expired := now.AddDate(0, 0, -60)
	recent := now.AddDate(0, 0, -1) // soft-deleted, still inside the window

	mkProject := func(name string) *models.Project {
		p := &models.Project{Name: name}
		require.NoError(t, db.Create(p).Error)
		return p
	}
	mkEnv := func(p *models.Project, name string) *models.Environment {
		e := &models.Environment{ProjectID: p.ID, Name: name}
		require.NoError(t, db.Create(e).Error)
		return e
	}
	// An expired user's secrets must survive (user -> secret, via OwnerID).
	uOld := &models.User{Username: "u-old", UsernameFolded: "u-old", EmailFolded: "u-old@example.com"}
	require.NoError(t, db.Create(uOld).Error)

	mkSecret := func(p *models.Project, e *models.Environment, name string, owner uint) *models.SecretNode {
		s := &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: name, OwnerID: owner}
		require.NoError(t, db.Create(s).Error)
		return s
	}

	// --- down: expired parents, children that must survive ---
	// pOld is past retention; its children are live or only recently deleted.
	pOld := mkProject("p-old")
	eOldLive := mkEnv(pOld, "live")
	eOldRecent := mkEnv(pOld, "recent")
	sOldLive := mkSecret(pOld, eOldLive, "s-live", uOld.ID)
	sOldRecent := mkSecret(pOld, eOldLive, "s-recent", uOld.ID)
	softDelete(t, db, "projects", pOld.ID, expired)
	softDelete(t, db, "environments", eOldRecent.ID, recent)
	softDelete(t, db, "secret_nodes", sOldRecent.ID, recent)

	// An expired environment's live secret must survive too (env -> secret).
	pLive := mkProject("p-live")
	eExpired := mkEnv(pLive, "expired")
	sUnderExpiredEnv := mkSecret(pLive, eExpired, "s-under-expired-env", 0)
	softDelete(t, db, "environments", eExpired.ID, expired)

	softDelete(t, db, "users", uOld.ID, expired)

	// --- up: expired children of parents that must survive ---
	pRecent := mkProject("p-recent")
	eUnderRecent := mkEnv(pRecent, "expired-child")
	sUnderRecent := mkSecret(pRecent, eUnderRecent, "s-expired-child", 0)
	softDelete(t, db, "projects", pRecent.ID, recent)
	softDelete(t, db, "environments", eUnderRecent.ID, expired)
	softDelete(t, db, "secret_nodes", sUnderRecent.ID, expired)

	eLiveParent := mkEnv(pLive, "live-parent")
	sExpiredUnderLive := mkSecret(pLive, eLiveParent, "s-expired-under-live", 0)
	softDelete(t, db, "secret_nodes", sExpiredUnderLive.ID, expired)

	res, err := c.PurgeExpiredSoftDeletes(context.Background(), before)
	require.NoError(t, err)

	// Each count reflects only that entity's own expired rows.
	assert.Equal(t, int64(1), res.Users, "users: only u-old")
	assert.Equal(t, int64(1), res.Projects, "projects: only p-old")
	assert.Equal(t, int64(2), res.Environments, "environments: only the two whose OWN deleted_at expired")
	assert.Equal(t, int64(2), res.Secrets, "secrets: only the two whose OWN deleted_at expired")

	// Purged on their own deleted_at.
	assert.False(t, rowExists(t, db, "users", uOld.ID))
	assert.False(t, rowExists(t, db, "projects", pOld.ID))
	assert.False(t, rowExists(t, db, "environments", eExpired.ID))
	assert.False(t, rowExists(t, db, "environments", eUnderRecent.ID), "up: expired env purged although its project is not expired")
	assert.False(t, rowExists(t, db, "secret_nodes", sUnderRecent.ID), "up: expired secret purged although its project is not expired")
	assert.False(t, rowExists(t, db, "secret_nodes", sExpiredUnderLive.ID), "up: expired secret purged although its environment is live")

	// No cascade down from a purged parent.
	assert.True(t, rowExists(t, db, "environments", eOldLive.ID), "down: purging a project must not purge its live environment")
	assert.True(t, rowExists(t, db, "environments", eOldRecent.ID), "down: purging a project must not purge its in-window environment")
	assert.True(t, rowExists(t, db, "secret_nodes", sOldLive.ID), "down: purging a project must not purge its live secret")
	assert.True(t, rowExists(t, db, "secret_nodes", sOldRecent.ID), "down: purging a project must not purge its in-window secret")
	assert.True(t, rowExists(t, db, "secret_nodes", sUnderExpiredEnv.ID), "down: purging an environment must not purge its live secret")

	// Parents of purged children survive.
	assert.True(t, rowExists(t, db, "projects", pRecent.ID), "up: an in-window project survives its children's purge")
	assert.True(t, rowExists(t, db, "projects", pLive.ID))
	assert.True(t, rowExists(t, db, "environments", eLiveParent.ID))
}

// TestPurgeExpiredSoftDeletes_EachEntityTypePurgedAlone is the issue's own
// suggested shape: with expired rows of exactly ONE entity type and none of
// its siblings, that type is still purged and no sibling is touched. It kills
// a gate in the orchestration itself (e.g. purging environments only when a
// project was purged), which the mixed fixture above cannot see because every
// type has an expired row there.
func TestPurgeExpiredSoftDeletes_EachEntityTypePurgedAlone(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	before := now.AddDate(0, 0, -30)
	expired := now.AddDate(0, 0, -60)

	for _, only := range []string{"users", "projects", "environments", "secret_nodes"} {
		t.Run(only, func(t *testing.T) {
			t.Parallel()
			c, db := newPurgeIndependenceCore(t)

			u := &models.User{Username: "u", UsernameFolded: "u", EmailFolded: "u@example.com"}
			require.NoError(t, db.Create(u).Error)
			p := &models.Project{Name: "p"}
			require.NoError(t, db.Create(p).Error)
			e := &models.Environment{ProjectID: p.ID, Name: "e"}
			require.NoError(t, db.Create(e).Error)
			s := &models.SecretNode{ProjectID: p.ID, EnvironmentID: e.ID, Name: "s", OwnerID: u.ID}
			require.NoError(t, db.Create(s).Error)
			ids := map[string]uint{"users": u.ID, "projects": p.ID, "environments": e.ID, "secret_nodes": s.ID}

			softDelete(t, db, only, ids[only], expired)

			res, err := c.PurgeExpiredSoftDeletes(context.Background(), before)
			require.NoError(t, err)
			got := map[string]int64{"users": res.Users, "projects": res.Projects, "environments": res.Environments, "secret_nodes": res.Secrets}
			for table, id := range ids {
				if table == only {
					assert.Equal(t, int64(1), got[table], "%s: its own expired row must be purged with no sibling expired", table)
					assert.False(t, rowExists(t, db, table, id))
				} else {
					assert.Equal(t, int64(0), got[table], "%s: must not be purged because %s was", table, only)
					assert.True(t, rowExists(t, db, table, id))
				}
			}
		})
	}
}
