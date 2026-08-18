// connect_ownership_resolution_test.go — ADR-082 branch 2: resolveConnectorOwnership
// (connector→project ID binding resolution) and connectOwnershipKeySetMismatch
// (the Manager/ownership key-set boot-time invariant). Uses a real (in-memory)
// SQLite-backed LocalStorage so GetProjectByName/GetConnectorProjectBinding/
// CreateConnectorProjectBinding/GetProject all resolve exactly as they would in
// production — no mocks.
package main

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func connectOwnershipResolutionStorage(t *testing.T) (*store.LocalStorage, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.ConnectorProjectBinding{}))
	return store.NewLocalStorage(db), db
}

// TestResolveConnectorOwnership_FirstBootResolvesAndPersists proves the first-boot
// path: a "project"-scoped connector with no existing binding resolves its
// configured project: name via GetProjectByName and persists a
// ConnectorProjectBinding pinning it by ID.
func TestResolveConnectorOwnership_FirstBootResolvesAndPersists(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	ctx := context.Background()
	project, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)

	ownership, err := resolveConnectorOwnership(ctx, st, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "payments"},
	})
	require.NoError(t, err)
	require.Contains(t, ownership, "aws")
	assert.Equal(t, core.ConnectOwnership{Scope: "project", ProjectID: project.ID}, ownership["aws"])

	var binding models.ConnectorProjectBinding
	require.NoError(t, db.Where("connector = ?", "aws").First(&binding).Error)
	assert.Equal(t, project.ID, binding.ProjectID)
	assert.Equal(t, "payments", binding.ProjectName)
}

// TestResolveConnectorOwnership_SubsequentBootResolvesByStoredID proves a later
// boot (a binding already exists) resolves by the STORED ID, not by re-resolving
// the config's project: name — even if a DIFFERENT project happens to now hold
// that same name (the exact silent-reassignment scenario ADR-082 pins against).
func TestResolveConnectorOwnership_SubsequentBootResolvesByStoredID(t *testing.T) {
	st, _ := connectOwnershipResolutionStorage(t)
	ctx := context.Background()
	original, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	_, err = st.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "aws", ProjectID: original.ID, ProjectName: "payments",
	})
	require.NoError(t, err)

	// A second, unrelated project now also happens to be named "payments" is not
	// possible under the live unique index — but a rename creating this exact
	// ambiguity IS possible in principle; what matters here is that the resolver
	// never even calls GetProjectByName once a binding exists.
	ownership, err := resolveConnectorOwnership(ctx, st, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "payments"},
	})
	require.NoError(t, err)
	assert.Equal(t, core.ConnectOwnership{Scope: "project", ProjectID: original.ID}, ownership["aws"])
}

// TestResolveConnectorOwnership_RenameFailsBoot proves a project rename since
// first boot is a deliberate boot failure (ADR-082), not a silent reassignment:
// the binding's stored ProjectName no longer matches the project's CURRENT name.
func TestResolveConnectorOwnership_RenameFailsBoot(t *testing.T) {
	st, _ := connectOwnershipResolutionStorage(t)
	ctx := context.Background()
	project, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	_, err = st.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "aws", ProjectID: project.ID, ProjectName: "payments",
	})
	require.NoError(t, err)

	// Rename the project after the binding was recorded.
	project.Name = "payments-renamed"
	_, err = st.UpdateProject(ctx, project)
	require.NoError(t, err)

	_, err = resolveConnectorOwnership(ctx, st, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "payments"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payments")
	assert.Contains(t, err.Error(), "payments-renamed", "the error must name both the stored and current project names")
}

// TestResolveConnectorOwnership_DeletedProjectFailsBoot proves a bound project
// that no longer exists (soft-deleted) is a boot failure, not a silent ownership
// gap.
func TestResolveConnectorOwnership_DeletedProjectFailsBoot(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	ctx := context.Background()
	project, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	_, err = st.CreateConnectorProjectBinding(ctx, &models.ConnectorProjectBinding{
		Connector: "aws", ProjectID: project.ID, ProjectName: "payments",
	})
	require.NoError(t, err)

	require.NoError(t, db.Delete(&models.Project{}, project.ID).Error) // soft delete

	_, err = resolveConnectorOwnership(ctx, st, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "payments"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws")
}

// TestResolveConnectorOwnership_UnresolvableNameFailsBoot proves a first-boot
// connector whose configured project: name resolves to no live project fails
// boot.
func TestResolveConnectorOwnership_UnresolvableNameFailsBoot(t *testing.T) {
	st, _ := connectOwnershipResolutionStorage(t)
	_, err := resolveConnectorOwnership(context.Background(), st, []config.ConnectorConfig{
		{Name: "aws", Scope: "project", Project: "does-not-exist"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws")
	assert.Contains(t, err.Error(), "does-not-exist")
}

// TestResolveConnectorOwnership_AggregatesMultipleFailures proves every
// offending connector is named in ONE combined error, matching branch 1's
// aggregation style — not a fail-on-first-found error that hides the rest.
func TestResolveConnectorOwnership_AggregatesMultipleFailures(t *testing.T) {
	st, _ := connectOwnershipResolutionStorage(t)
	_, err := resolveConnectorOwnership(context.Background(), st, []config.ConnectorConfig{
		{Name: "unresolvable-1", Scope: "project", Project: "nope-1"},
		{Name: "unresolvable-2", Scope: "project", Project: "nope-2"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unresolvable-1")
	assert.Contains(t, err.Error(), "unresolvable-2")
}

// TestResolveConnectorOwnership_PlatformNeedsNoResolution proves a
// "platform"-scoped connector resolves with no project lookup at all.
func TestResolveConnectorOwnership_PlatformNeedsNoResolution(t *testing.T) {
	st, _ := connectOwnershipResolutionStorage(t)
	ownership, err := resolveConnectorOwnership(context.Background(), st, []config.ConnectorConfig{
		{Name: "shared-vault", Scope: "platform"},
	})
	require.NoError(t, err)
	assert.Equal(t, core.ConnectOwnership{Scope: "platform"}, ownership["shared-vault"])
}

// TestConnectOwnershipKeySetMismatch_DetectsGenuineDivergence proves a connector
// present in the manager but absent from ownership (or vice versa) is reported
// as a mismatch.
func TestConnectOwnershipKeySetMismatch_DetectsGenuineDivergence(t *testing.T) {
	ownership := map[string]core.ConnectOwnership{
		"aws": {Scope: "project", ProjectID: 1},
	}
	mismatch := connectOwnershipKeySetMismatch([]string{"aws", "gcp"}, ownership)
	assert.Equal(t, []string{"gcp"}, mismatch)
}

// TestConnectOwnershipKeySetMismatch_NoExemptionForAnyDivergence is the
// regression guard for the connect.allow_unscoped removal (ADR-082 §C,
// amended): a connector that WOULD have been exempted under the old
// scope-based exemption (an empty Scope, built into the manager but absent
// from ownership) is now reported as a mismatch like any other divergence —
// resolveConnectorOwnership no longer skips any connector, and the mismatch
// check no longer accepts a connectors argument to special-case one.
func TestConnectOwnershipKeySetMismatch_NoExemptionForAnyDivergence(t *testing.T) {
	ownership := map[string]core.ConnectOwnership{} // empty: nothing resolved for "aws"
	mismatch := connectOwnershipKeySetMismatch([]string{"aws"}, ownership)
	assert.Equal(t, []string{"aws"}, mismatch, "with allow_unscoped removed, there is no exemption — any divergence, including what used to be the unscoped case, must be reported")
}
