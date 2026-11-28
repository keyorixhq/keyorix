package admin

import (
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestMain fails the package when a test, or an admin command it runs
// in-process, leaves a storage background job running (ADMIN-CLOSE-1; same
// check as internal/storage's TestMain). A Postgres storage from CreateStorage
// runs the role-permission generation integrity check until Close; an admin
// command that never closed its storage left that goroutine logging through the
// global logger for the rest of the binary, and a later test that captures log
// output raced with it (the TestBootLeavesStaleSaltPending_* DATA RACE). Any job
// still running once every test has returned is reported with the stack that
// started it. It only sees jobs on Postgres (KEYORIX_TEST_PG_DSN set): on
// SQLite no background job starts.
func TestMain(m *testing.M) {
	code := m.Run()
	if leaked := store.LiveBackgroundJobs(); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d storage background job(s) still running after every test returned; whoever built the storage must Close it. Started at:\n", len(leaked))
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
// the storage closed when t ends. Use it where a test builds a storage only to
// migrate or seed the database and drops the result.
func createStorageClosedAtCleanup(t testing.TB, cfg *config.Config) (corestorage.Storage, error) {
	t.Helper()
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err == nil {
		t.Cleanup(func() { closeStorage(st) })
	}
	return st, err
}
