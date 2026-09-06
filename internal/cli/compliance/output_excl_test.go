package compliance

// Regression tests for Group 2 (safe file writes): the compliance package's --output
// paths (inventory/controls CSV via emitCSV, evidence export JSON, permission-baseline
// JSON) used to write via raw os.WriteFile — no O_NOFOLLOW, no O_EXCL, silently
// overwriting/truncating whatever was already at --output. They now route through
// securefiles.SecureCreateFile, which refuses to create through OR overwrite a
// pre-existing path. See keyorix-private/adversarial-review/QUEUE.md "Group 2".

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmitCSV_RefusesPreexistingOutputFile(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("name,project\nnew,proj\n"))
	})
	dir := t.TempDir()
	outPath := filepath.Join(dir, "inv.csv")
	require.NoError(t, os.WriteFile(outPath, []byte("stale-csv-content"), 0o600))

	inventoryProject = 0
	inventoryOutput = outPath
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	err := inventoryCmd.RunE(nil, nil)
	require.Error(t, err, "a pre-existing --output path must now be refused, not silently overwritten")

	got, rerr := os.ReadFile(outPath)
	require.NoError(t, rerr)
	assert.Equal(t, "stale-csv-content", string(got), "the pre-existing file must be left completely untouched")
}

func TestExportCmd_RefusesPreexistingOutputFile(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"posture":{"ok":true}}}`))
	})
	dir := t.TempDir()
	outPath := filepath.Join(dir, "pack.json")
	require.NoError(t, os.WriteFile(outPath, []byte("stale-evidence-pack"), 0o600))

	exportOutput = outPath
	t.Cleanup(func() { exportOutput = "" })

	err := exportCmd.RunE(nil, nil)
	require.Error(t, err, "a pre-existing --output path must now be refused, not silently overwritten")

	got, rerr := os.ReadFile(outPath)
	require.NoError(t, rerr)
	assert.Equal(t, "stale-evidence-pack", string(got), "the pre-existing file must be left completely untouched")
}

func TestBaselineCmd_JSON_RefusesPreexistingOutputFile(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"rows":[]}}`))
	})
	dir := t.TempDir()
	outPath := filepath.Join(dir, "baseline.json")
	require.NoError(t, os.WriteFile(outPath, []byte("stale-baseline"), 0o600))

	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "json"
	baselineOutput = outPath

	err := baselineCmd.RunE(nil, nil)
	require.Error(t, err, "a pre-existing --output path must now be refused, not silently overwritten")

	got, rerr := os.ReadFile(outPath)
	require.NoError(t, rerr)
	assert.Equal(t, "stale-baseline", string(got), "the pre-existing file must be left completely untouched")
}
