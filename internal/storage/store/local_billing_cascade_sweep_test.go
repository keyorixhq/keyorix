// local_billing_cascade_sweep_test.go — partial-coverage sweep for
// local_billing.go's GetBillingReport pipeline: each sequential aggregation
// step's own DB-error branch AND the caller-level error-wrap branch it
// triggers, reached via newBrokenDB, partial migration, or
// dropTableAfterRows (shared helper, local_secrets_cascade_sweep_test.go) --
// billing.go uses .Table(...).Scan(...) throughout, which routes through
// GORM's "gorm:row" callback family, not "gorm:query".
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestGetBillingReport_AllProjectIDsFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), nil)
	require.Error(t, err)
}

func TestGetBillingReport_ProjectNamesFails(t *testing.T) {
	t.Parallel()
	ls := newBrokenDB(t)
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_SecretCountsFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{})
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_ReadsFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{})
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_WritesFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.AuditEvent{})
	dropTableAfterRows(t, ls.db, 2, "audit_events")
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_RotationsFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.AuditEvent{})
	dropTableAfterRows(t, ls.db, 3, "audit_events")
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_DistinctUsersFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.AuditEvent{})
	dropTableAfterRows(t, ls.db, 4, "audit_events")
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}

func TestGetBillingReport_MachineReadsFails(t *testing.T) {
	t.Parallel()
	ls := newPartialSecretsDB(t, &models.Project{}, &models.SecretNode{}, &models.AuditEvent{})
	dropTableAfterRows(t, ls.db, 5, "audit_events")
	_, err := ls.GetBillingReport(context.Background(), time.Now().Add(-time.Hour), time.Now(), []uint{1})
	require.Error(t, err)
}
