package core

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newEvidenceExportCore builds a real-SQLite core on an empty deployment, migrating
// the tables GenerateComplianceEvidence reads so the export runs end to end.
func newEvidenceExportCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{},
		&models.AuditEvent{}, &models.AnomalyAlert{}, &models.LegalHold{},
		&models.SoDPolicy{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.AccessRequest{},
	))
	now := time.Date(2026, 6, 14, 9, 30, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db, now
}

func TestExportComplianceEvidence_WritesFileAndAudits(t *testing.T) {
	ctx := context.Background()
	c, db, now := newEvidenceExportCore(t)
	dir := t.TempDir()

	res, err := c.ExportComplianceEvidence(ctx, dir)
	require.NoError(t, err)
	require.NotEmpty(t, res.Path)
	assert.Greater(t, res.Bytes, 0)

	// The file is named by the generation timestamp and lives under the output dir.
	wantName := "keyorix-evidence-" + now.UTC().Format(evidenceFileTimeLayout) + ".json"
	assert.Equal(t, filepath.Join(dir, wantName), res.Path)

	raw, err := os.ReadFile(res.Path)
	require.NoError(t, err)
	var ev ComplianceEvidence
	require.NoError(t, json.Unmarshal(raw, &ev), "exported file is valid evidence JSON")
	assert.False(t, ev.GeneratedAt.IsZero(), "evidence carries a generation time")
	require.NotNil(t, ev.Posture, "evidence embeds the posture")

	// The export is itself audited (system-actored) → forwarded to a SIEM.
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", "compliance.evidence_exported").Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

func TestExportComplianceEvidence_EmptyOutputDirErrors(t *testing.T) {
	c, _, _ := newEvidenceExportCore(t)
	_, err := c.ExportComplianceEvidence(context.Background(), "")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "output_dir"), "error names the misconfig")
}

type fakeEvidenceForwarder struct {
	calls int
	data  []byte
	err   error
}

func (f *fakeEvidenceForwarder) ForwardEvidence(_ context.Context, data []byte) error {
	f.calls++
	f.data = data
	return f.err
}

func TestExportComplianceEvidence_WebhookOnly(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newEvidenceExportCore(t)
	fwd := &fakeEvidenceForwarder{}
	c.SetEvidenceForwarder(fwd)

	res, err := c.ExportComplianceEvidence(ctx, "") // no dir → webhook is the only target
	require.NoError(t, err)
	assert.Equal(t, 1, fwd.calls)
	assert.Greater(t, len(fwd.data), 0)
	assert.Empty(t, res.Path)
	assert.Equal(t, []string{"webhook"}, res.Targets)

	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ?", "compliance.evidence_exported").Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

func TestExportComplianceEvidence_FileAndWebhook(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newEvidenceExportCore(t)
	fwd := &fakeEvidenceForwarder{}
	c.SetEvidenceForwarder(fwd)

	res, err := c.ExportComplianceEvidence(ctx, t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 1, fwd.calls)
	assert.NotEmpty(t, res.Path)
	assert.Len(t, res.Targets, 2, "delivered to both file and webhook")
}

func TestExportComplianceEvidence_WebhookFailureWithFileSucceeds(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newEvidenceExportCore(t)
	c.SetEvidenceForwarder(&fakeEvidenceForwarder{err: errors.New("boom")})

	res, err := c.ExportComplianceEvidence(ctx, t.TempDir())
	require.NoError(t, err, "a file was written, so a webhook failure is non-fatal")
	assert.NotEmpty(t, res.Path)
	assert.Equal(t, []string{"file:" + res.Path}, res.Targets, "the failed webhook is not listed as a target")
}

func TestExportComplianceEvidence_WebhookOnlyFailureErrors(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newEvidenceExportCore(t)
	c.SetEvidenceForwarder(&fakeEvidenceForwarder{err: errors.New("boom")})

	_, err := c.ExportComplianceEvidence(ctx, "") // webhook-only and it fails → fatal
	require.Error(t, err)
}
