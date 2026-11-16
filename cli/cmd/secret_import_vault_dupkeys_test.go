package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A vault-format import of n identical keys used to cost the YAML library O(n^2)
// time and memory (about 1.4 GB for 20000 lines, https://github.com/yaml/go-yaml/issues/510),
// which the 100 MiB size cap does not bound. parseVault now rejects the duplicate
// before decoding.
func TestParseVault_DuplicateKeysFailFastAndStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement; skipped in -short")
	}
	path := filepath.Join(t.TempDir(), "dup.yaml")
	if err := os.WriteFile(path, []byte(strings.Repeat("secret/a:\n", 20000)), 0o600); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := parseVault(path)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want a duplicate-key error, got %v", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
		t.Fatalf("parseVault allocated %d bytes on 20000 duplicate keys; expected a linear-cost rejection", alloc)
	}
}

func TestParseVault_DuplicateKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dup.yaml")
	content := "secret/a:\n  value: one\nsecret/a:\n  value: two\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseVault(path); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want a duplicate-key error, got %v", err)
	}
}
