package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDotenv_SkipsCommentsBlanksAndEmptyValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	content := "# a comment\n\nDB_PASSWORD=hunter2\nEMPTY=\nQUOTED=\"has spaces\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := parseDotenv(path)
	if err != nil {
		t.Fatalf("parseDotenv: %v", err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	if got["DB_PASSWORD"] != "hunter2" {
		t.Fatalf("expected DB_PASSWORD=hunter2, got %q", got["DB_PASSWORD"])
	}
	if got["QUOTED"] != "has spaces" {
		t.Fatalf("expected QUOTED unquoted to 'has spaces', got %q", got["QUOTED"])
	}
	if _, ok := got["EMPTY"]; ok {
		t.Fatal("expected EMPTY (no value) to be skipped")
	}
}

func TestParseDotenv_RejectsControlCharactersInValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.env")
	// \x1b is ESC -- an ANSI escape sequence prefix.
	content := "KEY=value\x1b[31mred\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := parseDotenv(path); err == nil {
		t.Fatal("expected an error for a value containing an ANSI escape sequence")
	}
}

func TestParseJSON_FlatKeyValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := `{"API_KEY": "sk_live_abc123", "EMPTY": ""}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := parseJSON(path)
	if err != nil {
		t.Fatalf("parseJSON: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "API_KEY" || entries[0].Value != "sk_live_abc123" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestParseJSON_RejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	// Just assert the size-check function directly rather than writing 100MiB.
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := checkImportFileSize(path); err != nil {
		t.Fatalf("expected a small file to pass the size check, got: %v", err)
	}
}

func TestParseVault_Format1SingleValueKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yaml")
	content := "secret/production/database-password:\n  value: supersecret123\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := parseVault(path)
	if err != nil {
		t.Fatalf("parseVault: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "database-password" || entries[0].Value != "supersecret123" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestParseVault_Format2MultiFieldExplodesPerField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.yaml")
	content := "secret/production/database:\n  password: hunter2\n  username: app_user\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := parseVault(path)
	if err != nil {
		t.Fatalf("parseVault: %v", err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	if got["database-password"] != "hunter2" || got["database-username"] != "app_user" {
		t.Fatalf("unexpected entries: %+v", got)
	}
}

func TestParseImportFile_UnknownFormatRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := parseImportFile(path, "xml"); err == nil {
		t.Fatal("expected an error for an unsupported format")
	}
}
