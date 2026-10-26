package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// jobsStartedBy returns the running storage background jobs whose start stack
// names fn, so tests running alongside do not count.
func jobsStartedBy(fn string) []string {
	var out []string
	for _, stack := range store.LiveBackgroundJobs() {
		if strings.Contains(stack, "."+fn+"(") {
			out = append(out, stack)
		}
	}
	return out
}

// TestCreateStorage_Postgres_CloseStopsBackgroundJobs: a factory-built
// Postgres storage runs the role-permission generation integrity check in the
// background, and Close stops that goroutine before it returns
// (FIX-3631-RACE-1). Before, a storage a test never closed kept the check
// running for the rest of the binary, logging through the global logger into
// a later test's captured log buffer (a -race failure in
// TestCreateLocalStorage_ExistingPath_LogsOpeningExisting). TestMain
// (background_job_leak_main_test.go) fails the package on any such leak.
func TestCreateStorage_Postgres_CloseStopsBackgroundJobs(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = pgIsolatedDatabaseDSN(t, pgTestDSN(t))
	const self = "TestCreateStorage_Postgres_CloseStopsBackgroundJobs"

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "the Postgres factory returns a *store.LocalStorage, got %T", st)

	running := jobsStartedBy(self)
	require.NotEmpty(t, running, "premise: CreateStorage started a background job")
	found := false
	for _, stack := range running {
		found = found || strings.Contains(stack, "StartRolePermissionsGenerationIntegrityCheck")
	}
	require.True(t, found, "premise: the integrity check is among the jobs CreateStorage started:\n%s", strings.Join(running, "\n"))

	require.NoError(t, ls.Close())
	require.Empty(t, jobsStartedBy(self), "Close must stop every background job before it returns")
}
