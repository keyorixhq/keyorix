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
	if byKind["rest"] < 100 {
		t.Errorf("expected >=100 REST routes, got %d", byKind["rest"])
	}
	if byKind["grpc"] < 50 {
		t.Errorf("expected >=50 gRPC methods, got %d", byKind["grpc"])
	}
	if byKind["job"] < 10 {
		t.Errorf("expected >=10 scheduled jobs, got %d", byKind["job"])
	}
	if byKind["cli"] < 20 {
		t.Errorf("expected >=20 CLI commands, got %d", byKind["cli"])
	}
}

func TestSmoke_DBTables(t *testing.T) {
	tables, err := DBTables(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tables: %d", len(tables))
	if len(tables) < 50 {
		t.Errorf("expected >=50 DB tables, got %d", len(tables))
	}
}

func TestSmoke_FileWriteSites(t *testing.T) {
	sites, err := FileWriteSites(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("file write sites: %d", len(sites))
	if len(sites) == 0 {
		t.Errorf("expected at least one file write site")
	}
}
