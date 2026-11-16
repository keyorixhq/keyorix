package backupfmt

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLoadArchive_InsertsInBoundedBatches pins the property restore's memory
// behaviour rests on (MIGRATE-SCALE-NOV-1, #3462): loadTable never hands the
// database more than batchSize rows in one insert, however many rows the table
// has, so the loader holds one batch at a time and not the table. The oracle is
// the insert statements the target database actually receives, not the loader's
// own counters: a callback on the target records the slice length of every
// INSERT into the table.
func TestLoadArchive_InsertsInBoundedBatches(t *testing.T) {
	const rows = 3*batchSize + 57 // three full batches and a partial one

	src := openTestDB(t)
	users := make([]models.User, rows)
	for i := range users {
		n := fmt.Sprintf("batch-user-%d", i)
		users[i] = models.User{Username: n, UsernameFolded: n, Email: n + "@example.invalid", EmailFolded: n + "@example.invalid"}
	}
	require.NoError(t, src.CreateInBatches(users, 100).Error)

	key := testManifestKey()
	var archive bytes.Buffer
	_, err := writeBackupModels(src, []any{&models.User{}}, 5, "", key, nil, nil, &archive)
	require.NoError(t, err)
	stagingDir := t.TempDir()
	manifest, err := ExtractArchive(&archive, stagingDir, 0, 0)
	require.NoError(t, err)
	require.Equal(t, int64(rows), manifest.Tables[0].RowCount)

	dst := openTestDB(t)
	var inserts []int
	require.NoError(t, dst.Callback().Create().Before("gorm:create").Register("test:record_insert_size", func(tx *gorm.DB) {
		if tx.Statement.Table != "users" {
			return
		}
		rv := tx.Statement.ReflectValue
		if rv.Kind() == reflect.Slice {
			inserts = append(inserts, rv.Len())
		} else {
			inserts = append(inserts, 1)
		}
	}))
	require.NoError(t, dst.Transaction(func(tx *gorm.DB) error {
		return LoadArchive(tx, manifest, stagingDir)
	}))

	total, largest := 0, 0
	for _, n := range inserts {
		total += n
		largest = max(largest, n)
	}
	require.Equal(t, rows, total, "every row is inserted exactly once")
	require.LessOrEqual(t, largest, batchSize, "no insert may carry more than batchSize rows")
	require.Len(t, inserts, 4, "%d rows load as three full batches and one partial batch, got inserts %v", rows, inserts)
}
