package credstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForgetSession_KeepsSettingsDropsSession(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(filepath.Join(dir, "keyorix", "credentials.yaml"))
	if err := s.Save(Credentials{ServerURL: "https://k.example", Token: "tok-secret", ActiveProject: "p1", CAFile: "/etc/k/ca.pem"}); err != nil {
		t.Fatal(err)
	}

	if err := s.ForgetSession(); err != nil {
		t.Fatalf("ForgetSession: %v", err)
	}

	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tok-secret") || strings.Contains(string(raw), "token") || strings.Contains(string(raw), "p1") {
		t.Fatalf("session material left in the file:\n%s", raw)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != (Credentials{ServerURL: "https://k.example", CAFile: "/etc/k/ca.pem"}) {
		t.Fatalf("Load = %+v, want only server_url and ca_file", got)
	}
	if info, _ := os.Stat(s.Path()); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Path()))
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestForgetSession_NothingStoredIsNotAnError(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "credentials.yaml"))
	if err := s.ForgetSession(); err != nil {
		t.Fatalf("ForgetSession with no file: %v", err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatalf("ForgetSession created the file (stat err = %v)", err)
	}
}

// A file Load refuses (mode wider than 0600) may still hold a token: it is removed, not kept.
func TestForgetSession_UnreadableFileIsRemoved(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "credentials.yaml"))
	if err := os.WriteFile(s.Path(), []byte("server_url: https://k\ntoken: tok-secret\nca_file: /ca.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetSession(); err != nil {
		t.Fatalf("ForgetSession: %v", err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatalf("a token-bearing file with mode 0644 survived (stat err = %v)", err)
	}
}

// With no setting to keep, the file goes away rather than lingering empty.
func TestForgetSession_NoSettingsLeftRemovesFile(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "credentials.yaml"))
	if err := s.Save(Credentials{Token: "tok-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetSession(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatalf("file survived (stat err = %v)", err)
	}
}
