package storage

import (
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestMain fails the package when a test leaves a storage background job
// running (FIX-3631-RACE-1). A Postgres storage from CreateStorage runs the
// role-permission generation integrity check until Close; a test that never
// closed it left that goroutine logging through the global logger for the rest
// of the binary, and a later test that captures log output raced with it
// (-race, merge-group run 40288380028). This check does not depend on -race
// timing: any job still running once every test has returned is reported with
// the stack (and so the test) that started it. It only sees jobs on Postgres
// (KEYORIX_TEST_PG_DSN set): on SQLite no background job starts.
func TestMain(m *testing.M) {
	code := m.Run()
	if leaked := store.LiveBackgroundJobs(); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d storage background job(s) still running after every test returned; the test that built the storage must Close it (createStorageClosedAtCleanup). Started at:\n", len(leaked))
		for _, stack := range leaked {
			fmt.Fprintln(os.Stderr, stack)
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// createStorageClosedAtCleanup is NewStorageFactory().CreateStorage(cfg) with
// the storage closed when t ends (before any cleanup registered earlier, such
// as dropping the test's database). Use it for every storage a test does not
// close itself.
func createStorageClosedAtCleanup(t testing.TB, cfg *config.Config) (storage.Storage, error) {
	t.Helper()
	st, err := NewStorageFactory().CreateStorage(cfg)
	if c, ok := st.(interface{ Close() error }); ok && err == nil {
		t.Cleanup(func() { _ = c.Close() })
	}
	return st, err
}
