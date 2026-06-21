package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newMaxReadsCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // sqlite: serialize connections (statements stay atomic)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}, db
}

// seedMaxReadsSecret creates a secret with the given max_reads and one version.
func seedMaxReadsSecret(t *testing.T, c *KeyorixCore, max int) uint {
	t.Helper()
	ctx := context.Background()
	maxReads := max
	s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "one-shot", ProjectID: 1, EnvironmentID: 1, Type: "password",
		IsSecret: true, MaxReads: &maxReads, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: s.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	return s.ID
}

func TestMaxReads_SequentialStopsAtCap(t *testing.T) {
	c, _ := newMaxReadsCore(t)
	id := seedMaxReadsSecret(t, c, 3)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := c.GetSecretValue(ctx, id)
		require.NoError(t, err, "read %d should be within the cap", i+1)
	}
	_, err := c.GetSecretValue(ctx, id)
	require.Error(t, err, "the 4th read must be denied")
	assert.Contains(t, err.Error(), i18n.T("ErrorMaxReadsExceeded", nil))
}

// The race fix: N concurrent reads of a max-reads=K secret must yield exactly K
// successes, never more. Before the atomic check-and-increment, concurrent readers
// could all pass the in-memory check and exceed the cap.
func TestMaxReads_ConcurrentNeverExceedsCap(t *testing.T) {
	c, db := newMaxReadsCore(t)
	const cap = 5
	const readers = 50
	id := seedMaxReadsSecret(t, c, cap)

	var success int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.GetSecretValue(context.Background(), id); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(cap), success, "exactly cap reads may succeed under concurrency")

	// The persisted read_count must never overshoot the cap either.
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", id).First(&v).Error)
	assert.LessOrEqual(t, v.ReadCount, cap, "read_count must not exceed the cap")
}
