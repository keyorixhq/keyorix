// local_secret_dependencies.go — secret dependency-graph edge persistence (ADR-052).
// Each row is a directed edge "dependent depends on depends_on" within one project;
// the core layer builds the graph from a project's edges for impact analysis and
// rotation ordering. For the remote equivalent see remote_secret_dependencies.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (ls *LocalStorage) CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	if err := ls.db.WithContext(ctx).Create(d).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return d, nil
}

func (ls *LocalStorage) GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error) {
	var d models.SecretDependency
	if err := ls.db.WithContext(ctx).First(&d, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &d, nil
}

func (ls *LocalStorage) ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	var rows []*models.SecretDependency
	if err := ls.db.WithContext(ctx).Where("project_id = ?", projectID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// ListSecretDependenciesForProjectForUpdate is ListSecretDependenciesForProject,
// adding SELECT … FOR UPDATE on Postgres so a cycle-check read inside a
// transaction serializes against a concurrent writer racing to add an edge in the
// same project (#260 — see AddSecretDependency). SQLite has no row-level lock, so
// the clause is omitted there and the caller (secretDependencyMu) serializes
// in-process; SQLite is always single-process, so that suffices.
func (ls *LocalStorage) ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	q := ls.db.WithContext(ctx)
	if ls.db.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []*models.SecretDependency
	if err := q.Where("project_id = ?", projectID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) DeleteSecretDependency(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretDependency{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// CreateSecretDependencyExclusive is the storage-layer half of #260's fix (see the
// interface doc, internal/core/storage/interface.go): it runs the SAME duplicate/cycle
// validation AddSecretDependency (internal/core/secret_dependencies.go) used to
// orchestrate itself across ListSecretDependenciesForProjectForUpdate +
// CreateSecretDependency, but now as ONE call wrapped in a single real DB transaction —
// so the guarantee survives being called over HTTP by RemoteStorage's implementation
// (remote_secret_dependencies.go), where no transaction can span two separate round
// trips.
func (ls *LocalStorage) CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) { // NOSONAR -- cognitive complexity 18, suppress go:S3776
	var created *models.SecretDependency
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var edges []*models.SecretDependency
		if err := q.Where("project_id = ?", d.ProjectID).Order("id ASC").Find(&edges).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, e := range edges {
			if e.DependentSecretID == d.DependentSecretID && e.DependsOnSecretID == d.DependsOnSecretID {
				return storage.ErrDuplicateSecretDependency
			}
		}
		if secretDependencyReachable(edges, d.DependsOnSecretID, d.DependentSecretID) {
			return storage.ErrSecretDependencyCycle
		}
		if err := tx.Create(d).Error; err != nil {
			if isUniqueViolation(err) {
				// Belt-and-suspenders: idx_secret_dep_edge caught a concurrent insert of
				// the exact same pair that committed between this transaction's own read
				// above and its write (possible on Postgres if the project had ZERO
				// existing edges to lock — see the interface doc's parity note).
				return storage.ErrDuplicateSecretDependency
			}
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		created = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// secretDependencyReachable reports whether `to` is reachable from `from` following
// depends-on edges (from depends on … depends on to). Mirrors
// internal/core/secret_dependencies.go's dependencyReachable exactly (that package
// cannot be imported here — internal/core depends on this package, not the reverse —
// so this is intentionally duplicated rather than shared; keep both in sync, and see
// TestDependencyReachable/TestSecretDependencyReachable for the shared truth table both
// must satisfy).
func secretDependencyReachable(edges []*models.SecretDependency, from, to uint) bool {
	adj := make(map[uint][]uint)
	for _, e := range edges {
		adj[e.DependentSecretID] = append(adj[e.DependentSecretID], e.DependsOnSecretID)
	}
	seen := map[uint]bool{from: true}
	stack := []uint{from}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range adj[n] {
			if next == to {
				return true
			}
			if !seen[next] {
				seen[next] = true
				stack = append(stack, next)
			}
		}
	}
	return false
}
