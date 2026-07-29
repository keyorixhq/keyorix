// local_billing.go — Per-project billing report query for LocalStorage.
//
// Covers: GetBillingReport
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_billing.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetBillingReport returns per-project usage stats for the half-open interval
// [from, to). When projectIDs is nil or empty, stats are returned for all
// non-deleted projects that have at least one active secret or any audit
// activity in the window. Projects with no secrets and no activity are omitted
// to keep the report concise.
func (ls *LocalStorage) GetBillingReport(ctx context.Context, from, to time.Time, projectIDs []uint) (*storage.BillingReport, error) {
	allProjects := len(projectIDs) == 0

	// --- Step 1: determine the project set ---
	if allProjects {
		type idRow struct{ ID uint }
		var rows []idRow
		if err := ls.db.WithContext(ctx).
			Table("projects").
			Select("id").
			Where("deleted_at IS NULL").
			Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			projectIDs = append(projectIDs, r.ID)
		}
	}
	if len(projectIDs) == 0 {
		return &storage.BillingReport{
			From:        from,
			To:          to,
			GeneratedAt: time.Now().UTC(),
			Projects:    []storage.BillingProjectStat{},
		}, nil
	}

	// --- Step 2: fetch project names in one query ---
	type projectRow struct {
		ID   uint
		Name string
	}
	var projRows []projectRow
	if err := ls.db.WithContext(ctx).
		Table("projects").
		Select("id, name").
		Where("id IN ?", projectIDs).
		Scan(&projRows).Error; err != nil {
		return nil, err
	}
	nameMap := make(map[uint]string, len(projRows))
	for _, p := range projRows {
		nameMap[p.ID] = p.Name
	}

	// --- Step 3: aggregate per project ---
	type counts struct {
		SecretCount     int64
		SecretReads     int64
		SecretWrites    int64
		SecretRotations int64
		UniqueUsers     int
		MachineReads    int64
	}

	statsMap := make(map[uint]*counts, len(projectIDs))
	for _, id := range projectIDs {
		statsMap[id] = &counts{}
	}

	// 3a. SecretCount — active leaf secrets
	type secretRow struct {
		ProjectID uint
		Count     int64
	}
	var secretRows []secretRow
	if err := ls.db.WithContext(ctx).
		Table("secret_nodes").
		Select("project_id, COUNT(*) AS count").
		Where("project_id IN ? AND is_secret = ? AND deleted_at IS NULL", projectIDs, true).
		Group("project_id").
		Scan(&secretRows).Error; err != nil {
		return nil, err
	}
	for _, r := range secretRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.SecretCount = r.Count
		}
	}

	// 3b. SecretReads — secret.read events in window
	type readRow struct {
		ProjectID uint
		Count     int64
	}
	var readRows []readRow
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(*) AS count").
		Where("project_id IN ? AND event_type = ? AND success = ? AND event_time >= ? AND event_time < ?",
			projectIDs, "secret.read", true, from, to).
		Group("project_id").
		Scan(&readRows).Error; err != nil {
		return nil, err
	}
	for _, r := range readRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.SecretReads = r.Count
		}
	}

	// 3c. SecretWrites — secret.create + secret.update + secret.rotate
	var writeRows []readRow
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(*) AS count").
		Where("project_id IN ? AND event_type IN ? AND success = ? AND event_time >= ? AND event_time < ?",
			projectIDs, []string{"secret.create", "secret.update", "secret.rotate"}, true, from, to).
		Group("project_id").
		Scan(&writeRows).Error; err != nil {
		return nil, err
	}
	for _, r := range writeRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.SecretWrites = r.Count
		}
	}

	// 3d. SecretRotations — secret.rotate only
	var rotRows []readRow
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(*) AS count").
		Where("project_id IN ? AND event_type = ? AND success = ? AND event_time >= ? AND event_time < ?",
			projectIDs, "secret.rotate", true, from, to).
		Group("project_id").
		Scan(&rotRows).Error; err != nil {
		return nil, err
	}
	for _, r := range rotRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.SecretRotations = r.Count
		}
	}

	// 3e. UniqueUsers — distinct human user_ids in window
	type userRow struct {
		ProjectID uint
		Count     int
	}
	var userRows []userRow
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(DISTINCT user_id) AS count").
		Where("project_id IN ? AND actor_type = ? AND event_time >= ? AND event_time < ?",
			projectIDs, "user", from, to).
		Group("project_id").
		Scan(&userRows).Error; err != nil {
		return nil, err
	}
	for _, r := range userRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.UniqueUsers = r.Count
		}
	}

	// 3f. MachineReads — secret.read by machine actors
	var machRows []readRow
	if err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("project_id, COUNT(*) AS count").
		Where("project_id IN ? AND event_type = ? AND actor_type = ? AND event_time >= ? AND event_time < ?",
			projectIDs, "secret.read", "machine", from, to).
		Group("project_id").
		Scan(&machRows).Error; err != nil {
		return nil, err
	}
	for _, r := range machRows {
		if c, ok := statsMap[r.ProjectID]; ok {
			c.MachineReads = r.Count
		}
	}

	// --- Step 4: build result, filtering zero-activity / no-secret projects ---
	var stats []storage.BillingProjectStat
	var totals storage.BillingTotals

	for _, id := range projectIDs {
		c := statsMap[id]
		// Omit projects with no secrets AND no activity
		if c.SecretCount == 0 && c.SecretReads == 0 && c.SecretWrites == 0 {
			continue
		}
		name := nameMap[id]
		if name == "" {
			name = ""
		}
		stat := storage.BillingProjectStat{
			ProjectID:       id,
			ProjectName:     name,
			SecretCount:     c.SecretCount,
			SecretReads:     c.SecretReads,
			SecretWrites:    c.SecretWrites,
			SecretRotations: c.SecretRotations,
			UniqueUsers:     c.UniqueUsers,
			MachineReads:    c.MachineReads,
		}
		stats = append(stats, stat)

		totals.SecretCount += c.SecretCount
		totals.SecretReads += c.SecretReads
		totals.SecretWrites += c.SecretWrites
		totals.SecretRotations += c.SecretRotations
		totals.UniqueUsers += c.UniqueUsers
		totals.MachineReads += c.MachineReads
	}
	totals.Projects = len(stats)

	if stats == nil {
		stats = []storage.BillingProjectStat{}
	}

	return &storage.BillingReport{
		From:        from,
		To:          to,
		GeneratedAt: time.Now().UTC(),
		Projects:    stats,
		Totals:      totals,
	}, nil
}
