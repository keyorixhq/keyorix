// secret_metadata_cache.go — the read-path metadata cache (PERF-3,
// docs/specs/read-path-caching.md): an in-process, per-LocalStorage-instance
// cache for the three rows GetSecret/GetLatestSecretVersion/
// GetSecretAccessSchedule fetch on every secret read. A cache hit still
// issues one live, indexed generation-check query — it never trusts an
// in-memory value against a write it hasn't independently observed from the
// database. This mirrors server/middleware/auth.go's tokenCache design
// principle (see that file's own header and server/middleware/INVARIANTS.md
// INV-MW-01..11): cache the expensive, mostly-static DATA, never the
// revocation/authorization DECISION — nothing here changes what
// AuthorizeSecret/AuthorizePrincipal decide, only how cheaply the data they
// and the handler read is served.
//
// # The generation signal is derived from the columns actually cached
//
// A timestamp alone is NOT a sufficient generation, and both ways it can fail
// were found live on this PR's own CI. The rule the three signals below follow
// is: a generation must change whenever ANY column of the cached value
// changes, so it is derived from those columns rather than from a timestamp
// that only some writers happen to advance.
//
//   - secret_nodes: (updated_at, read_count). UpdatedAt alone covers every
//     writer that goes through GORM's auto-timestamp callback — which includes
//     Save() (the full-struct write UpdateSecret uses) and every
//     Update/Updates call, but NOT UpdateColumn. The one UpdateColumn writer
//     of this table, TryIncrementSecretNodeReadCount (the #133 max-reads
//     budget), therefore left updated_at untouched while changing read_count,
//     which the cached node exposes. A warm cache then served read_count=0
//     indefinitely, and RotateSecret's read-modify-write (GetSecret →
//     Save) wrote that stale zero back, handing a burn-after-N-reads secret a
//     fresh budget — TestMaxReads_SurvivesRotateAndRollback, red on
//     c87207ac3. Including read_count in the generation closes it without
//     touching updated_at's user-visible meaning and without adding a
//     statement to any write path.
//     (Deliberately NOT done: bumping updated_at from the read path. That
//     changes a timestamp the UI and the rotation-due reports read, and
//     updated_at is load-bearing elsewhere — see the version signal below.)
//   - secret_versions, for GetLatestSecretVersion: (count, max(version_number),
//     sum(read_count)) over the secret's own versions. This table has no
//     updated_at column at all, so the first implementation borrowed
//     secret_nodes.updated_at and had CreateSecretVersion bump it. That bump
//     was reverted: it put a second UPDATE on secret_nodes inside rotation's
//     transaction, and — worse — made the cache's invalidation depend on
//     timestamp RESOLUTION. Two rotations of one secret landing inside the
//     same stored updated_at tick produce equal generations, so
//     storeNextSecretVersion's retry loop kept re-reading the SAME cached
//     "latest" version, recomputed the same next version_number, and burned
//     all 20 attempts against the unique index
//     (TestConcurrency_RotateSecret_NoDuplicateVersionNumbers, red on
//     86dea1220 in CI under load). A content-derived generation has no clock
//     in it: a new version changes count and max(version_number)
//     immediately, a deleted version (local_purge.go) changes count, and a
//     read_count increment changes sum(read_count).
//   - secret_access_schedules: the schedule row's own updated_at, read in the
//     SAME query as the row. Same-row, so there is no window between reading
//     the stamp and reading the data for a write to commit into.
//
// Known gap, named rather than left implicit: internal/encryption/sweep.go's
// DEK rotation sweep rewrites secret_versions.encrypted_value without
// changing count, max(version_number) or sum(read_count), so a warm
// latest-version entry can outlive a rewrap. That sweep runs only under the
// exclusive key lock (ADR-010, RotateDEKWithSweep), the operator-triggered
// stopped-server class, and its failure mode is a decrypt error against a
// retired key — fail-closed, not a disclosure. Covered by
// TestSecretVersionGenerationCoversEveryWriter's own documented exception
// list, so a NEW writer of this table fails that test instead of silently
// joining the exception.
//
// Deliberately a FIELD on *LocalStorage, not a package-level global: a
// package-level cache would be silently shared across every LocalStorage
// instance in one test binary, which would make a cross-replica Postgres
// test (two LocalStorage instances, two *gorm.DB pools, one shared schema —
// see postgres_contention_helpers_test.go) pass regardless of whether the
// DB-generation invalidation actually works, the same hazard that file's own
// header documents for a single shared storage.Storage. Each NewLocalStorage
// call gets its own fresh cache; WithTransaction's tx-scoped copy shares its
// parent's pointer (same as auditChainMu etc.) — reads inside a transaction
// go through the SAME *gorm.DB handle doing the generation check, so an
// uncommitted write earlier in that transaction is correctly visible
// (read-your-own-writes), and nothing here weakens that.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// nodeGeneration is the generation signal for a cached secret_nodes row:
// every column of the row that any writer can change must move one of these
// two fields. updated_at covers GORM's auto-timestamp writers (Save,
// Update, Updates); read_count covers the one UpdateColumn writer, which
// bypasses that callback. See this file's header for the live defect that
// made the second field necessary.
//
// The timestamp is stored as int64 nanoseconds, not a time.Time: that is what
// makes this type `comparable` and therefore usable as a cacheGeneration at
// all, and it removes the chance of someone comparing two time.Time stamps
// with `==` by hand (which also compares the monotonic reading and the
// *time.Location pointer, so two reads of the same column can compare
// unequal). See read_path_cache.go's cacheGeneration doc comment.
type nodeGeneration struct {
	updatedAtUnixNano int64
	readCount         int
}

func (nodeGeneration) isCacheGeneration() {}

// versionsGeneration is the generation signal for a cached "latest version of
// secret N": derived from the version rows themselves, with no timestamp in
// it, because secret_versions has no updated_at column and because a
// timestamp's resolution is not a safe invalidation boundary for a table
// written in a tight retry loop (see this file's header).
type versionsGeneration struct {
	count            int64
	maxVersionNumber int64
	sumReadCount     int64
}

func (versionsGeneration) isCacheGeneration() {}

// scheduleGeneration is the schedule row's own updated_at — the same-row case
// (cachedReadSameRow), read in the same query as the row it stamps.
type scheduleGeneration struct {
	updatedAtUnixNano int64
}

func (scheduleGeneration) isCacheGeneration() {}

// secretMetadataCache is three independently generation-checked genCaches, one
// per generation signal. Node and latest-version are separate maps rather than
// two halves of one entry precisely because they are validated against
// DIFFERENT signals (secret_nodes columns vs the secret_versions aggregate) and
// so cannot share a stamp — which is also what retired the mergeNode/
// mergeVersion pair that existed only to stop GetSecret and
// GetLatestSecretVersion clobbering each other's half.
//
// A nil value in the versions cache is a cached NEGATIVE ("this generation has
// no version row"), distinguishable from "nothing cached" by the entry's
// presence. The schedules cache never caches a negative: a secret with no
// schedule row has no updated_at to stamp one with, so that case always falls
// through to a live read (a documented perf-only limitation, not a correctness
// gap).
type secretMetadataCache struct {
	nodes     *genCache[uint, nodeGeneration, *models.SecretNode]
	versions  *genCache[uint, versionsGeneration, *models.SecretVersion]
	schedules *genCache[uint, scheduleGeneration, *models.SecretAccessSchedule]
}

func newSecretMetadataCache() *secretMetadataCache {
	return &secretMetadataCache{
		nodes:     newGenCache[uint, nodeGeneration, *models.SecretNode](),
		versions:  newGenCache[uint, versionsGeneration, *models.SecretVersion](),
		schedules: newGenCache[uint, scheduleGeneration, *models.SecretAccessSchedule](),
	}
}

// getNode/getVersion/getSchedule are read-only probes into the raw entries,
// used by tests that assert on cache state. They cannot create staleness, so
// read_path_cache_guard_test.go does not restrict them.
func (c *secretMetadataCache) getNode(id uint) (genCacheEntry[nodeGeneration, *models.SecretNode], bool) {
	return peekCachedEntry(c.nodes, id)
}

func (c *secretMetadataCache) getVersion(secretNodeID uint) (genCacheEntry[versionsGeneration, *models.SecretVersion], bool) {
	return peekCachedEntry(c.versions, secretNodeID)
}

func (c *secretMetadataCache) getSchedule(secretNodeID uint) (genCacheEntry[scheduleGeneration, *models.SecretAccessSchedule], bool) {
	return peekCachedEntry(c.schedules, secretNodeID)
}

// evictNode drops both halves for one secret. Eviction is always safe (it can
// only cost a future miss) — see genCache.drop's own comment for why the
// guard's scope deliberately excludes it.
func (c *secretMetadataCache) evictNode(id uint) {
	invalidateCachedRead(c.nodes, id)
	invalidateCachedRead(c.versions, id)
}

// liveNodeGeneration reads ONLY the generation columns of secret_nodes for id
// (updated_at, read_count), applying the same soft-delete scope GetSecret
// itself relies on (Model(&SecretNode{}) auto-scopes deleted_at IS NULL).
// Returns (zero, false, nil) when the row doesn't exist or is soft-deleted —
// the caller treats that identically to a cache miss, which correctly falls
// through to the live GetSecret call that will itself return
// ErrRecordNotFound. Returns (zero, false, err) on any other DB error — the
// fail-closed path: the caller must treat a generation-check error exactly
// like a miss, never like "assume unchanged."
func liveNodeGeneration(ctx context.Context, db *gorm.DB, id uint) (nodeGeneration, bool, error) {
	var row struct {
		UpdatedAt time.Time
		ReadCount int
	}
	err := db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("updated_at", "read_count").Where(sqlWhereID, id).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nodeGeneration{}, false, nil
		}
		return nodeGeneration{}, false, err
	}
	return nodeGeneration{updatedAtUnixNano: row.UpdatedAt.UnixNano(), readCount: row.ReadCount}, true, nil
}

// liveVersionsGeneration reads the aggregate generation of secretNodeID's
// version rows in one indexed query (secret_versions is indexed on
// secret_node_id). Unlike the node and schedule signals it has no "found"
// notion: a secret with no versions legitimately aggregates to the zero
// generation, and that zero is itself a valid stamp — GetLatestSecretVersion
// caches the "no version exists" answer under it, and the first
// CreateSecretVersion moves count and max(version_number) off zero. An error
// is still fail-closed: the caller treats it as a miss and caches nothing.
func liveVersionsGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (versionsGeneration, error) {
	var row struct {
		Cnt    int64
		MaxVer int64
		SumRc  int64
	}
	err := db.WithContext(ctx).Model(&models.SecretVersion{}).
		Select("COUNT(*) AS cnt, COALESCE(MAX(version_number), 0) AS max_ver, COALESCE(SUM(read_count), 0) AS sum_rc").
		Where(sqlWhereSecretNodeID, secretNodeID).Take(&row).Error
	if err != nil {
		return versionsGeneration{}, err
	}
	return versionsGeneration{count: row.Cnt, maxVersionNumber: row.MaxVer, sumReadCount: row.SumRc}, nil
}

// liveScheduleGeneration is the schedule table's stamp-only read, used ONLY to
// validate a warm entry; the entry itself is stamped with the row's own
// updated_at read in the same query as the row (GetSecretAccessSchedule), so
// there is no read-data-then-read-stamp window. SecretAccessSchedule has no
// soft-delete column, so "not found" here always means
// DeleteSecretAccessSchedule actually removed the row.
func liveScheduleGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (scheduleGeneration, bool, error) {
	var row struct{ UpdatedAt time.Time }
	err := db.WithContext(ctx).Model(&models.SecretAccessSchedule{}).
		Select("updated_at").Where(sqlWhereSecretNodeID, secretNodeID).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return scheduleGeneration{}, false, nil
		}
		return scheduleGeneration{}, false, err
	}
	return scheduleGeneration{updatedAtUnixNano: row.UpdatedAt.UnixNano()}, true, nil
}
