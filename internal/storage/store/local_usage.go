// local_usage.go — Per-project usage report query for LocalStorage.
//
// Covers: GetProjectUsageStats
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_usage.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetProjectUsageStats returns per-project usage stats over the past windowDays
// days. When projectIDs is nil or empty, stats are returned for ALL projects
// that have at least one active secret or at least one secret.read audit event
// in the window.
func (ls *LocalStorage) GetProjectUsageStats(ctx context.Context, projectIDs []uint, windowDays int) ([]storage.ProjectUsageStat, error) {
	since := time.Now().UTC().AddDate(0, 0, -windowDays)
	allProjects := len(projectIDs) == 0

	// --- Query 1: active secret counts per project ---
	type secretRow struct {
		ProjectID uint
		Count     int64
	}
	var secretRows []secretRow
	q := ls.db.WithContext(ctx).
		Table("secret_nodes").
		Select("project_id, COUNT(*) AS count").
		Where("deleted_at IS NULL AND is_secret = ?", true)
	if !allProjects {
		q = q.Where("project_id IN ?", projectIDs)
	}
	if err := q.Group("project_id").Scan(&secretRows).Error; err != nil {
		return nil, err
	}

	// --- Query 2: read counts + unique reader counts per project ---
	type readRow struct {
		ProjectID uint
		Reads     int64
		Readers   int
	}
	var readRows []readRow
	rq := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(*) AS reads, COUNT(DISTINCT COALESCE(user_id, 0)) AS readers").
		Where("event_type = ? AND (success = ? OR success IS NULL) AND event_time >= ?", "secret.read", true, since).
		Where("project_id IS NOT NULL")
	if !allProjects {
		rq = rq.Where("project_id IN ?", projectIDs)
	}
	if err := rq.Group("project_id").Scan(&readRows).Error; err != nil {
		return nil, err
	}

	// Merge results into a map keyed by project_id
	type merged struct {
		secrets int64
		reads   int64
		readers int
	}
	statsMap := make(map[uint]*merged)
	for _, r := range secretRows {
		if statsMap[r.ProjectID] == nil {
			statsMap[r.ProjectID] = &merged{}
		}
		statsMap[r.ProjectID].secrets = r.Count
	}
	for _, r := range readRows {
		if statsMap[r.ProjectID] == nil {
			statsMap[r.ProjectID] = &merged{}
		}
		statsMap[r.ProjectID].reads = r.Reads
		statsMap[r.ProjectID].readers = r.Readers
	}

	if len(statsMap) == 0 {
		return nil, nil
	}

	// Collect project IDs we need names for
	ids := make([]uint, 0, len(statsMap))
	for id := range statsMap {
		ids = append(ids, id)
	}

	// --- Query 3: project names ---
	type projectRow struct {
		ID   uint
		Name string
	}
	var projRows []projectRow
	if err := ls.db.WithContext(ctx).
		Table("projects").
		Select("id, name").
		Where("id IN ?", ids).
		Scan(&projRows).Error; err != nil {
		return nil, err
	}
	nameMap := make(map[uint]string, len(projRows))
	for _, p := range projRows {
		nameMap[p.ID] = p.Name
	}

	// Build result slice
	result := make([]storage.ProjectUsageStat, 0, len(statsMap))
	for id, m := range statsMap {
		result = append(result, storage.ProjectUsageStat{
			ProjectID:     id,
			ProjectName:   nameMap[id],
			SecretCount:   m.secrets,
			ReadsInWindow: m.reads,
			UniqueReaders: m.readers,
		})
	}
	return result, nil
}
