package audit

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateChainEncoding_CommandWiring(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range AuditCmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["migrate-chain-encoding"], "missing subcommand migrate-chain-encoding")
	assert.NotNil(t, migrateChainCmd.Flags().Lookup("confirm"), "migrate-chain-encoding missing --confirm")
}

func TestMigrateChainEncoding_DefaultIsDryRun(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"dry_run":true,"rows_migrated":42,"unchained_rows_skipped":3,"head_id":45,"head_hash":"abc123"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out bytes.Buffer
	migrateChainCmd.SetOut(&out)
	flagMigrateConfirm = false
	require.NoError(t, migrateChainCmd.RunE(migrateChainCmd, nil))

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/audit/migrate-chain-encoding", gotPath)
	assert.Equal(t, "dry_run=true", gotQuery, "without --confirm the call must request the safe dry-run path, never omit dry_run")
}

func TestMigrateChainEncoding_ConfirmAppliesForReal(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"dry_run":false,"rows_migrated":42,"unchained_rows_skipped":3,"head_id":45,"head_hash":"abc123","anchor_row_id":9,"anchor_new_entry_hash":"def456"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out bytes.Buffer
	migrateChainCmd.SetOut(&out)
	flagMigrateConfirm = true
	defer func() { flagMigrateConfirm = false }()
	require.NoError(t, migrateChainCmd.RunE(migrateChainCmd, nil))

	assert.Equal(t, "dry_run=false", gotQuery, "--confirm must explicitly opt out of the safe default")
}

func TestMigrateChainEncoding_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"insufficient permissions"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagMigrateConfirm = false
	err := migrateChainCmd.RunE(migrateChainCmd, nil)
	require.Error(t, err)
}
