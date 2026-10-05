// secret_metadata_cache.go — the read-path metadata cache (PERF-3,
// docs/specs/read-path-caching.md): an in-process, per-LocalStorage-instance
// cache for the three rows GetSecret/GetLatestSecretVersion/
// GetSecretAccessSchedule fetch on every secret read. A cache hit still
// issues one live, indexed generation-check query (secret_nodes.updated_at or
// secret_access_schedules.updated_at) — it never trusts an in-memory value
// against a write it hasn't independently observed from the database. This
// mirrors server/middleware/auth.go's tokenCache design principle (see that
// file's own header and server/middleware/INVARIANTS.md INV-MW-01..11):
// cache the expensive, mostly-static DATA, never the revocation/
// authorization DECISION — nothing here changes what
// AuthorizeSecret/AuthorizePrincipal decide, only how cheaply the data they
// and the handler read is served.
//
// Generation signal is UpdatedAt (GORM's own built-in auto-timestamp), not a
// hand-added counter column — found the hard way: a custom BeforeUpdate hook
// bumping a dedicated column via tx.Statement.SetColumn(col, gorm.Expr(...))
// works for a targeted Update/Updates(map) call but is SILENTLY A NO-OP for
// a full-struct Save() (confirmed empirically — see this PR's description
// for the two debug-test traces), and Save() is exactly what UpdateSecret
// and several other write paths use. UpdatedAt sidesteps this entirely
// because GORM's own internal timestamp callback sets it directly via
// struct-field reflection (not via the hook SetColumn API), which DOES
// survive Save() — confirmed the same way. A soft-delete does NOT touch
// UpdatedAt (confirmed empirically too), but that's harmless here: the
// generation-check queries below apply the same soft-delete scope GetSecret
// itself relies on, so a deleted row simply stops matching ("not found"),
// independent of whether its timestamp moved.
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
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

type secretNodeCacheEntry struct {
	generation    time.Time
	node          *models.SecretNode
	hasVersion    bool
	latestVersion *models.SecretVersion
}

type secretScheduleCacheEntry struct {
	generation  time.Time
	hasSchedule bool
	schedule    *models.SecretAccessSchedule
}

// secretMetadataCache is the whole cache: two independently generation-checked
// maps, because a schedule write touches a different table (and therefore a
// different generation signal) than a node/version write.
type secretMetadataCache struct {
	mu        sync.Mutex
	nodes     map[uint]secretNodeCacheEntry
	schedules map[uint]secretScheduleCacheEntry
}

func newSecretMetadataCache() *secretMetadataCache {
	return &secretMetadataCache{
		nodes:     make(map[uint]secretNodeCacheEntry),
		schedules: make(map[uint]secretScheduleCacheEntry),
	}
}

func (c *secretMetadataCache) getNode(id uint) (secretNodeCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.nodes[id]
	return e, ok
}

// mergeNode records node under generation, preserving an already-cached
// latestVersion/hasVersion from the SAME generation (GetSecret and
// GetLatestSecretVersion populate the same map entry independently — one
// must not clobber whichever piece the other already cached). A stale
// (older) generation already present is simply replaced, version info and
// all, since it's known-outdated the instant a newer generation is
// observed.
func (c *secretMetadataCache) mergeNode(id uint, generation time.Time, node *models.SecretNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.nodes[id]
	if ok && existing.generation.Equal(generation) {
		existing.node = node
		c.nodes[id] = existing
		return
	}
	c.nodes[id] = secretNodeCacheEntry{generation: generation, node: node}
}

// mergeVersion is mergeNode's counterpart for the latest-version half of the
// same cache entry — see mergeNode's doc comment.
func (c *secretMetadataCache) mergeVersion(id uint, generation time.Time, version *models.SecretVersion, hasVersion bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.nodes[id]
	if ok && existing.generation.Equal(generation) {
		existing.hasVersion = hasVersion
		existing.latestVersion = version
		c.nodes[id] = existing
		return
	}
	c.nodes[id] = secretNodeCacheEntry{generation: generation, hasVersion: hasVersion, latestVersion: version}
}

func (c *secretMetadataCache) evictNode(id uint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, id)
}

func (c *secretMetadataCache) getSchedule(secretNodeID uint) (secretScheduleCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.schedules[secretNodeID]
	return e, ok
}

func (c *secretMetadataCache) setSchedule(secretNodeID uint, e secretScheduleCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.schedules[secretNodeID] = e
}

func (c *secretMetadataCache) evictSchedule(secretNodeID uint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.schedules, secretNodeID)
}

// liveNodeGeneration reads ONLY secret_nodes.updated_at for id, applying the
// same soft-delete scope GetSecret itself relies on (Model(&SecretNode{})
// auto-scopes deleted_at IS NULL). Returns (zero, false, nil) when the row
// doesn't exist or is soft-deleted — the caller treats that identically to a
// cache miss, which correctly falls through to the live GetSecret call that
// will itself return ErrRecordNotFound. Returns (zero, false, err) on any
// other DB error — the fail-closed path: the caller must treat a
// generation-check error exactly like a miss, never like "assume unchanged."
func liveNodeGeneration(ctx context.Context, db *gorm.DB, id uint) (time.Time, bool, error) {
	var row struct{ UpdatedAt time.Time }
	err := db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("updated_at").Where(sqlWhereID, id).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	return row.UpdatedAt, true, nil
}

// liveScheduleGeneration is liveNodeGeneration's schedule-table counterpart.
// SecretAccessSchedule has no soft-delete column, so "not found" here always
// means DeleteSecretAccessSchedule actually removed the row.
func liveScheduleGeneration(ctx context.Context, db *gorm.DB, secretNodeID uint) (time.Time, bool, error) {
	var row struct{ UpdatedAt time.Time }
	err := db.WithContext(ctx).Model(&models.SecretAccessSchedule{}).
		Select("updated_at").Where(sqlWhereSecretNodeID, secretNodeID).Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	return row.UpdatedAt, true, nil
}
