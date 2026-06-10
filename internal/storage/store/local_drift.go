// local_drift.go — cross-environment drift projection for LocalStorage.
//
// Drift detection compares the set of secret keys (by name) across a project's
// environments. This query supplies the raw rows — one per secret, carrying only
// the fields the pivot needs — without reading any secret value.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// ListProjectSecretsForDrift returns the drift projection for every real secret
// in the project. Folders (is_secret = false) are excluded, as are secrets whose
// environment has been soft-deleted (so a deleted environment never shows up as
// a phantom column). The JOIN also pins environment_id to the project, mirroring
// ListSecrets' cross-project-leakage guard.
func (ls *LocalStorage) ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]storage.DriftSecretRow, error) {
	type row struct {
		EnvironmentID uint
		Name          string
		Type          string
		HasExpiration bool
		HasMaxReads   bool
	}
	var rows []row
	if err := ls.db.WithContext(ctx).
		Table("secret_nodes AS s").
		Select("s.environment_id AS environment_id, s.name AS name, s.type AS type, "+
			"(s.expiration IS NOT NULL) AS has_expiration, (s.max_reads IS NOT NULL) AS has_max_reads").
		Joins("JOIN environments e ON e.id = s.environment_id").
		Where("s.project_id = ?", projectID).
		Where("e.project_id = ?", projectID).
		Where("e.deleted_at IS NULL").
		Where("s.deleted_at IS NULL").
		Where("s.is_secret = ?", true).
		Order("s.name ASC, s.environment_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]storage.DriftSecretRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, storage.DriftSecretRow{
			EnvironmentID: r.EnvironmentID,
			Name:          r.Name,
			Type:          r.Type,
			HasExpiration: r.HasExpiration,
			HasMaxReads:   r.HasMaxReads,
		})
	}
	return out, nil
}
