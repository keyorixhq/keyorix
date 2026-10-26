package main

// shutdown_flush_test.go — #3377: the graceful-shutdown path must write the
// secret-read denial summary rows that are still open at SIGTERM, not only the
// last-used stamps, and must not hang on a slow database while doing so.

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newShutdownDenialWorld is a core on an in-memory SQLite database with one
// connection; refuse records one refused read of secretID by user 1.
func newShutdownDenialWorld(t *testing.T) (c *core.KeyorixCore, db *gorm.DB, refuse func(secretID uint)) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SystemMetadata{},
		&models.SecretNode{}, &models.User{}, &models.Group{}))
	c = core.NewKeyorixCore(store.NewLocalStorage(db))
	refuse = func(secretID uint) {
		ctx, note := core.WithSecretReadDenialNote(context.Background(), core.SecretReadPathRESTGet)
		c.RecordNotedSecretReadDenial(ctx, note,
			core.SecretReadDenialActor{UserID: 1, Username: "u1", IP: "10.0.0.9"},
			core.SecretReadDenialTarget{SecretID: secretID}, core.SecretReadDeniedForbidden)
	}
	return c, db, refuse
}

func refusedReadRows(t *testing.T, db *gorm.DB) []models.AuditEvent {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, db.Where("event_type = ? AND success = ?", "secret.read", false).Order("id").Find(&rows).Error)
	return rows
}

func TestShutdown_FlushesOpenSecretReadDenialSummary(t *testing.T) {
	c, db, refuse := newShutdownDenialWorld(t)
	const n = 5
	for range n {
		refuse(42)
	}
	require.Len(t, refusedReadRows(t, db), 1, "only the first refusal of the window is written before shutdown")

	flushSecretReadDenialsOnShutdown(c)

	rows := refusedReadRows(t, db)
	require.Len(t, rows, 2, "shutdown must write the open window's summary row (the other refusals)")
	var summary struct {
		Count      int  `json:"count"`
		Aggregated bool `json:"aggregated"`
	}
	require.NoError(t, json.Unmarshal([]byte(rows[1].Diff), &summary))
	assert.True(t, summary.Aggregated)
	assert.Equal(t, n-1, summary.Count, "the summary row carries the refusals after the window's first row")
}

// lockedLogBuffer collects log output; the write still in flight after the
// bound may log while the test reads.
type lockedLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// shutdownDenialFlushBound is the bound the review asked for (#3602).
const shutdownDenialFlushBound = 10 * time.Second

// A database that does not answer must not hold shutdown past the 10 s bound:
// the flush gives up, and the rows it could not write are named in a SECURITY
// log line. Each audit write has its own 10 s limit, so three open windows
// took 30 s before the bound.
func TestShutdown_SecretReadDenialFlushIsBoundedOnSlowDatabase(t *testing.T) {
	c, db, refuse := newShutdownDenialWorld(t)
	const windows = 3
	for target := range uint(windows) {
		refuse(100 + target)
		refuse(100 + target)
	}
	require.Len(t, refusedReadRows(t, db), windows, "one immediate row per window")

	// Hold the only connection: every write from here on waits for it.
	tx := db.Begin()
	require.NoError(t, tx.Error)
	released := false
	release := func() {
		if !released {
			released = true
			require.NoError(t, tx.Rollback().Error)
		}
	}
	t.Cleanup(release)

	var buf lockedLogBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		flushSecretReadDenialsOnShutdown(c)
	}()
	select {
	case <-done:
	case <-time.After(shutdownDenialFlushBound + 5*time.Second):
		release() // let the stuck write finish so the goroutine can end
		<-done
		t.Fatalf("shutdown flush did not return within %s + 5s on a stuck database", shutdownDenialFlushBound)
	}
	assert.GreaterOrEqual(t, time.Since(start), shutdownDenialFlushBound-time.Second, "the flush waits up to its bound")
	// The in-flight write may hit its own 10 s limit just before the bound.
	assert.Regexp(t, `SECURITY: shutdown: [23] refused-secret-read summary row\(s\) NOT written`, buf.String())
}
