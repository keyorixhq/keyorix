package securefiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateFile_RefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "out"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(dir, "out", []byte("new"), 0o600); err == nil {
		t.Fatal("CreateFile must refuse to overwrite an existing file")
	}
	got, _ := os.ReadFile(filepath.Join(dir, "out"))
	if string(got) != "old" {
		t.Fatalf("existing file was modified: %q", got)
	}
}

func TestCreateFile_RefusesSymlinkLeaf(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(string, string, []byte, os.FileMode) error{
		"CreateFile": CreateFile, "CreateFileSync": CreateFileSync, "WriteFile": WriteFile,
	} {
		if err := fn(dir, "out", []byte("x"), 0o600); err == nil {
			t.Fatalf("%s must refuse to write through a symlink", name)
		}
	}
	got, _ := os.ReadFile(target)
	if string(got) != "victim" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestWriteFile_OverwritesAndFixesMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out")
	if err := os.WriteFile(p, []byte("old-longer-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(dir, "out", []byte("new"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestCreateFileSync_CreatesWithMode(t *testing.T) {
	dir := t.TempDir()
	if err := CreateFileSync(dir, "key.pem", []byte("k"), 0o600); err != nil {
		t.Fatalf("CreateFileSync: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}
