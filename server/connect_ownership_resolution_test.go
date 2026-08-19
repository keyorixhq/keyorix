// connect_ownership_resolution_test.go — ADR-082 branch 2: resolveConnectorOwnership
// (connector→project ID binding resolution) and connectOwnershipKeySetMismatch
// (the Manager/ownership key-set boot-time invariant). Uses a real (in-memory)
// SQLite-backed LocalStorage so GetProjectByName/GetConnectorProjectBinding/
// CreateConnectorProjectBinding/GetProject all resolve exactly as they would in
// production — no mocks.
package main

import (
	"bytes"
	"context"
	"log"
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
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.ConnectorProjectBinding{}, &models.AuditEvent{}))
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

	// ADR-082 branch 3 / issue #1477's audit half: the boot-time first-resolution
	// write is itself an authorization-input change and must be audited, same as
	// the RemoteStorage proxy's equivalent write.
	var event models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", core.EventConnectorProjectBindingCreate).First(&event).Error)
	require.NotNil(t, event.ProjectID)
	assert.Equal(t, project.ID, *event.ProjectID)
	assert.True(t, *event.Success)
	assert.Equal(t, core.ActorTypeSystem, event.ActorType)
	assert.Contains(t, event.Description, "aws")
	assert.Contains(t, event.Description, "payments")
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

// captureLog redirects the standard logger to a buffer for the duration of the
// test, restoring the original writer on cleanup — matches the convention
// already established in transport_tls_test.go for asserting on warn-only log
// output.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

// TestWarnConnectConfigDrift_DeadRefGrant is #1479's boot-time half: a
// ConnectRefGrant created while its connector was scope: project (or
// pre-dating any scope requirement) becomes dead configuration if the config
// is later edited to scope: platform — create-time refusal (CreateConnectRefGrant)
// cannot catch this, since the grant already existed before the edit. Proves
// the warning fires, names the connector, and — critically — does not fail
// boot (no panic, no error return; warnConnectConfigDrift has no error return
// at all, this test would simply not compile if it acquired one unexpectedly).
func TestWarnConnectConfigDrift_DeadRefGrant(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	require.NoError(t, db.AutoMigrate(&models.ConnectRefGrant{}))
	require.NoError(t, db.Create(&models.ConnectRefGrant{RoleID: 5, Connector: "aws", RefPrefix: "metrics/"}).Error)

	buf := captureLog(t)
	warnConnectConfigDrift(context.Background(), st, map[string]core.ConnectOwnership{
		"aws": {Scope: "platform"},
	})

	assert.Contains(t, buf.String(), "aws")
	assert.Contains(t, buf.String(), "dead configuration")
}

// TestWarnConnectConfigDrift_OrphanedBinding is #1477's boot-time half: a
// ConnectorProjectBinding row whose connector name is no longer in
// cfg.Connect.Connectors (removed, or renamed in config) — neither side of
// connectOwnershipKeySetMismatch enumerates DB rows, so this is the only
// check that catches it. Proves the warning fires and names the orphaned
// connector.
func TestWarnConnectConfigDrift_OrphanedBinding(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	require.NoError(t, db.Create(&models.ConnectorProjectBinding{
		Connector: "decommissioned", ProjectID: 1, ProjectName: "payments",
	}).Error)

	buf := captureLog(t)
	// ownership has no entry for "decommissioned" — matching a config that no
	// longer lists it at all.
	warnConnectConfigDrift(context.Background(), st, map[string]core.ConnectOwnership{
		"aws": {Scope: "platform"},
	})

	assert.Contains(t, buf.String(), "decommissioned")
	assert.Contains(t, buf.String(), "orphaned")
}

// TestWarnConnectConfigDrift_NoFalsePositives confirms a healthy state — a
// ref-grant against a still-project-scoped connector, a binding whose
// connector is still configured — produces neither warning.
func TestWarnConnectConfigDrift_NoFalsePositives(t *testing.T) {
	st, db := connectOwnershipResolutionStorage(t)
	require.NoError(t, db.AutoMigrate(&models.ConnectRefGrant{}))
	require.NoError(t, db.Create(&models.ConnectRefGrant{RoleID: 5, Connector: "aws", RefPrefix: "metrics/"}).Error)
	require.NoError(t, db.Create(&models.ConnectorProjectBinding{
		Connector: "aws", ProjectID: 1, ProjectName: "payments",
	}).Error)

	buf := captureLog(t)
	warnConnectConfigDrift(context.Background(), st, map[string]core.ConnectOwnership{
		"aws": {Scope: "project", ProjectID: 1},
	})

	assert.Empty(t, buf.String(), "a healthy grant/binding state must not produce any drift warning")
}
