// recover_admin_alert_kill_resume_test.go pins the claim docs/UPGRADING.md section 6j
// makes about the first start after an upgrade: the one-off audit scan is windowed
// and resumable. It drives RunRecoverAdminAlerting on a real file-backed SQLite
// database of about 100,000 audit rows, stops the scan after the first window
// (the process "killed" once that window's mark is saved) and resumes it with a
// new connection and a new core, as a restart would.
package core

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestRunRecoverAdminAlerting_100kRows_WindowBoundaryAndResumeAfterKill(t *testing.T) {
	const w = recoverAdminAlertScanWindow
	const (
		lastOfFirstWindow   = w     // recover-admin use on the last id of window 1
		firstOfSecondWindow = w + 1 // recover-admin use on the first id of window 2
		total               = w + 50
	)
	path := filepath.Join(t.TempDir(), "audit.db")
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
		require.NoError(t, err)
		return db
	}
	db := open()
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}, &models.NotificationChannel{}))

	// 99,999 ordinary rows, a recover-admin use at each side of the window
	// boundary (ids 100000 and 100001), then ordinary rows up to 100,050.
	bulkInsertAuditRows(t, db, w-1, "secret.read")
	bulkInsertAuditRows(t, db, 1, recoverAdminAuditEventType)
	bulkInsertAuditRows(t, db, 1, recoverAdminAuditEventType)
	bulkInsertAuditRows(t, db, total-w-1, "secret.read")
	var maxID int64
	require.NoError(t, db.Raw("SELECT COALESCE(MAX(id), 0) FROM audit_events").Scan(&maxID).Error)
	require.EqualValues(t, total, maxID)
	require.NoError(t, db.Create(&models.NotificationChannel{
		Name: "ops-webhook", Type: "webhook", URLEnc: plaintextURLEnc("https://fake-webhook.test/hook"), Enabled: true,
	}).Error)

	var mu sync.Mutex
	seen := map[uint]int{}
	transport := &fakeWebhookTransport{capture: func(body []byte) {
		var p struct {
			ID uint `json:"audit_event_id"`
		}
		require.NoError(t, json.Unmarshal(body, &p))
		mu.Lock()
		seen[p.ID]++
		mu.Unlock()
	}}
	newCore := func(db *gorm.DB) *KeyorixCore {
		c := NewKeyorixCore(store.NewLocalStorage(db))
		c.httpClient = &http.Client{Transport: transport}
		return c
	}
	mark := func(db *gorm.DB) string {
		var m models.SystemMetadata
		if err := db.Where("key = ?", recoverAdminAlertHighWaterKey).Take(&m).Error; err != nil {
			return ""
		}
		return m.Value
	}

	// First start: "kill" the process right after window 1's mark is saved.
	ctx, kill := context.WithCancel(context.Background())
	defer kill()
	require.NoError(t, db.Callback().Create().After("gorm:create").Register("killafterwindow1", func(tx *gorm.DB) {
		if m, ok := tx.Statement.Dest.(*models.SystemMetadata); ok &&
			m.Key == recoverAdminAlertHighWaterKey && m.Value == "100000" {
			kill()
		}
	}))
	n, err := newCore(db).RunRecoverAdminAlerting(ctx)
	require.ErrorIs(t, err, context.Canceled, "the scan stops once the process is killed")
	assert.Equal(t, 1, n, "window 1 alerted the use on its last id (the boundary row belongs to window 1)")
	assert.Equal(t, "100000", mark(db), "the mark is the end of the last finished window")
	assert.Equal(t, map[uint]int{lastOfFirstWindow: 1}, seen)

	// Restart: a new connection and a new core on the same file continue from the
	// saved mark: window 2 only, so the boundary use is not alerted again and the
	// use on the first id after the boundary is not skipped.
	db2 := open()
	n, err = newCore(db2).RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "the resumed scan alerts only the use after the boundary")
	assert.Equal(t, "100050", mark(db2), "the mark ends at the highest audit id")
	assert.Equal(t, map[uint]int{lastOfFirstWindow: 1, firstOfSecondWindow: 1}, seen,
		"every use alerted exactly once across the kill")

	// Afterwards the job reads only new rows: nothing to do.
	n, err = newCore(db2).RunRecoverAdminAlerting(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Equal(t, map[uint]int{lastOfFirstWindow: 1, firstOfSecondWindow: 1}, seen)
}
