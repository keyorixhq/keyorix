// local_machine_identities.go — machine identity persistence (ADR-023).
//
// For the remote (HTTP) equivalent see remote_machine_identities.go.
package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error) {
	if err := ls.db.WithContext(ctx).Create(m).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return m, nil
}

func (ls *LocalStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	var m models.MachineIdentity
	if err := ls.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

// LockMachineIdentityForUpdate re-reads a machine identity, adding SELECT … FOR
// UPDATE on Postgres so a read-modify-write inside a transaction serializes against
// concurrent writers of the same row (#388: TransitionMachineIdentity relies on this
// to keep "revoked is terminal" atomic — see machine_identities.go). SQLite has no
// row-level lock, so the clause is omitted there and the transaction alone
// serializes it; SQLite is always single-process, so that suffices.
func (ls *LocalStorage) LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	q := ls.db.WithContext(ctx)
	if ls.db.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var m models.MachineIdentity
	if err := q.First(&m, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

func (ls *LocalStorage) UpdateMachineIdentity(ctx context.Context, m *models.MachineIdentity) error {
	if err := ls.db.WithContext(ctx).Save(m).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// TransitionMachineIdentityState persists m's full row via a conditional UPDATE
// gated on the row's CURRENT state still being fromState (#388, see the
// interface doc in internal/core/storage/interface.go for why this exists
// alongside — not instead of — LockMachineIdentityForUpdate). Mirrors
// UpdateProjectInvitation's `WHERE id = ? AND state = ?` + `Select("*")` shape
// exactly, so every field the caller mutated on m (State, UpdatedAt, RevokedAt,
// ...) is persisted in the same statement, not just a hardcoded column subset.
func (ls *LocalStorage) TransitionMachineIdentityState(ctx context.Context, m *models.MachineIdentity, fromState string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MachineIdentity{}).
		Where("id = ? AND state = ?", m.ID, fromState).
		Select("*").
		Updates(m)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

func (ls *LocalStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	var rows []*models.MachineIdentity
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// ListAllMachineIdentities returns every machine identity across all projects.
func (ls *LocalStorage) ListAllMachineIdentities(ctx context.Context) ([]*models.MachineIdentity, error) {
	var rows []*models.MachineIdentity
	err := ls.db.WithContext(ctx).Order("created_at DESC").Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	return countByClassification(ctx, ls.db, &models.MachineIdentity{})
}

// machineIdentityStateActive mirrors core.MachineActive (the store package cannot
// import core: core already imports storage/store). Keeps
// CountStaleMachineIdentitiesByProject's "only ACTIVE identities count as stale"
// rule in lockstep with ListStaleMachineIdentities's in-memory filter.
const machineIdentityStateActive = "active"

// CountStaleMachineIdentitiesByProject returns, for every project in projectIDs,
// the count of ACTIVE machine identities not seen since olderThan (an identity
// never seen counts from its creation time) — the same definition
// ListStaleMachineIdentities uses, but as a single grouped query instead of one
// ListMachineIdentities call per project. Used by the deployment-wide hygiene
// rollup (#393) instead of fanning out one call per project. A project with no
// stale machine identities is simply absent from the returned map.
func (ls *LocalStorage) CountStaleMachineIdentitiesByProject(ctx context.Context, projectIDs []uint, olderThan time.Time) (map[uint]int, error) {
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}
	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).Model(&models.MachineIdentity{}).
		Select("project_id, COUNT(*) AS n").
		Where("project_id IN ?", projectIDs).
		Where("state = ?", machineIdentityStateActive).
		Where("(last_seen_at IS NULL AND created_at < ?) OR last_seen_at < ?", olderThan, olderThan).
		Group("project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}
