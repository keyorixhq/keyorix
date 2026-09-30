package statemap

import (
	"os"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/statemap -> repo root
	return filepath.Join(wd, "..", "..")
}

func TestSmoke_AllEntries(t *testing.T) {
	entries, err := AllEntries(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string]int{}
	for _, e := range entries {
		byKind[e.Kind]++
	}
	t.Logf("entries: %+v (total %d)", byKind, len(entries))
	// Floors set near the actual counts at the time these fixes landed (rest 372,
	// grpc 86, job 17, cli 310, mcp 2) rather than round numbers far below them --
	// a floor that only catches a near-total extractor collapse (e.g. the earlier
	// ">=100" REST floor against an actual 372) gives no real signal that the
	// extractor is still working. These are allowed to grow with the codebase;
	// they exist to catch a REGRESSION (an extractor silently returning far
	// fewer than it used to), not to pin an exact count -- that's
	// TestCompletenessGuard_EntrypointsAndStoresMatchCode's job.
	if byKind["rest"] < 350 {
		t.Errorf("expected >=350 REST routes, got %d", byKind["rest"])
	}
	if byKind["grpc"] < 80 {
		t.Errorf("expected >=80 gRPC methods, got %d", byKind["grpc"])
	}
	if byKind["job"] < 15 {
		t.Errorf("expected >=15 scheduled jobs, got %d", byKind["job"])
	}
	if byKind["cli"] < 290 {
		t.Errorf("expected >=290 CLI commands, got %d", byKind["cli"])
	}
	if byKind["mcp"] < 2 {
		t.Errorf("expected >=2 MCP tools, got %d", byKind["mcp"])
	}
}

func TestSmoke_DBTables(t *testing.T) {
	tables, err := DBTables(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tables: %d", len(tables))
	if len(tables) < 70 {
		t.Errorf("expected >=70 DB tables, got %d", len(tables))
	}
}

func TestSmoke_FileWriteSites(t *testing.T) {
	sites, err := FileWriteSites(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("file write sites: %d", len(sites))
	if len(sites) < 45 {
		t.Errorf("expected >=45 file-write call sites (os.WriteFile/os.Create/os.OpenFile/securefiles.Secure*), got %d", len(sites))
	}
}
