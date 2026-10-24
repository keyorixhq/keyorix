// restore_journal_boot_test.go -- RESTORE-OVERWRITE-FIX-1: the boot-time
// key-set check refuses to start while an interrupted `admin restore` left its
// journal (internal/restorejournal), on both backends and whether or not
// encryption is enabled, and passes again once the journal is gone.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

func TestVerifyKeyFileSetConsistency_RefusesWhileRestoreJournalExists(t *testing.T) {
	cases := map[string]func(dir string) *config.Config{
		"sqlite-no-encryption": func(dir string) *config.Config {
			cfg := &config.Config{}
			cfg.Storage.Type = "local"
			cfg.Storage.Database.Path = filepath.Join(dir, "secrets.db")
			return cfg
		},
		"postgres": func(dir string) *config.Config {
			cfg := &config.Config{}
			cfg.Storage.Type = "postgres"
			cfg.Storage.Encryption.Enabled = true
			cfg.Storage.Encryption.SaltPath = filepath.Join(dir, "kek.salt")
			cfg.Storage.Encryption.DEKPath = filepath.Join(dir, "dek.key")
			return cfg
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := mk(dir)
			if err := verifyKeyFileSetConsistency(cfg); err != nil {
				t.Fatalf("no journal: boot check must pass: %v", err)
			}
			journal := filepath.Join(dir, restorejournal.FileName)
			if err := os.WriteFile(journal, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			err := verifyKeyFileSetConsistency(cfg)
			if err == nil || !strings.Contains(err.Error(), "admin restore --recover") {
				t.Fatalf("journal present: boot check must refuse and name --recover, got %v", err)
			}
			if err := os.Remove(journal); err != nil {
				t.Fatal(err)
			}
			if err := verifyKeyFileSetConsistency(cfg); err != nil {
				t.Fatalf("journal removed: boot check must pass again: %v", err)
			}
		})
	}
}
