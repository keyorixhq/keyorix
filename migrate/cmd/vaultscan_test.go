package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

func TestRunVaultScan_RequiresOutput(t *testing.T) {
	scanOutput = ""
	t.Cleanup(func() { scanOutput = "" })
	if err := runVaultScan(scanCmd, nil); err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("runVaultScan with no --output = %v, want an error naming --output", err)
	}
}

// TestRunVaultScan_EndToEnd runs the real cobra command against a fake Vault, exactly the shape
// an operator invocation takes, and asserts all three report files are written with matching
// content — the redaction guarantee itself is healthscan's own responsibility
// (redact_test.go); this test proves the command wiring (flag resolution, healthscan.New,
// healthscan.Run, and the three file writes) doesn't drop or duplicate anything end to end.
func TestRunVaultScan_EndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no checks registered yet in G1 -- every path 404s.
	}))
	defer srv.Close()

	dir := t.TempDir()
	prefix := filepath.Join(dir, "report")

	scanAddr = srv.URL
	scanToken = "root-token"
	scanOutput = prefix
	t.Cleanup(func() {
		scanAddr, scanToken, scanOutput = "", "", ""
	})

	var stderr bytes.Buffer
	scanCmd.SetErr(&stderr)

	if err := runVaultScan(scanCmd, nil); err != nil {
		t.Fatalf("runVaultScan: %v", err)
	}

	for _, ext := range []string{".md", ".json", ".html"} {
		path := prefix + ext
		data, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
		if err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", path)
		}
	}

	jsonData, err := os.ReadFile(prefix + ".json") // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SchemaVersion int `json:"schema_version"`
		healthscan.Report
	}
	if err := json.Unmarshal(jsonData, &got); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}
	if got.SchemaVersion != healthscan.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", got.SchemaVersion, healthscan.SchemaVersion)
	}
	if got.VaultAddr != srv.URL {
		t.Errorf("vault_addr = %q, want %q", got.VaultAddr, srv.URL)
	}
}

func TestRunVaultScan_TLSSkipVerifyWarnsOnStderr(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	prefix := filepath.Join(dir, "report")

	scanAddr = srv.URL
	scanToken = "root-token"
	scanOutput = prefix
	scanTLSSkipVerify = true
	t.Cleanup(func() {
		scanAddr, scanToken, scanOutput = "", "", ""
		scanTLSSkipVerify = false
	})

	var stderr bytes.Buffer
	cmd := scanCmd
	cmd.SetErr(&stderr)

	if err := runVaultScan(cmd, nil); err != nil {
		t.Fatalf("runVaultScan: %v", err)
	}
	if !strings.Contains(stderr.String(), "WARNING") || !strings.Contains(stderr.String(), "tls-skip-verify") {
		t.Fatalf("expected a loud --tls-skip-verify warning on stderr, got: %q", stderr.String())
	}
}
