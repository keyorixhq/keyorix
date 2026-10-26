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
	"github.com/keyorixhq/keyorix/internal/keyfiles"
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

// When a restore journal AND a key set that no longer matches its manifest are
// both present (a restore killed after installing some of the archive's key
// files, before the manifest), boot names the journal and --recover, not the
// manifest mismatch: the mismatch is that restore's own half-installed state,
// and its remedy ("restore the whole set again") is refused while the journal
// exists. With the journal gone the manifest check still refuses on its own,
// so neither check hides a set the other would have let through.
func TestVerifyKeyFileSetConsistency_JournalRefusalComesBeforeManifestMismatch(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = filepath.Join(dir, "kek.salt")
	cfg.Storage.Encryption.DEKPath = filepath.Join(dir, "dek.key")
	for _, name := range []string{"kek.salt", "dek.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("live-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ks, err := keyfiles.NewSetWriter(&cfg.Storage.Encryption, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.CommitManifestFromDisk(keyfiles.OpFirstBoot, ks.Required()...); err != nil {
		t.Fatal(err)
	}
	if err := verifyKeyFileSetConsistency(cfg); err != nil {
		t.Fatalf("a recorded set with no journal must pass: %v", err)
	}

	// The archive's dek.key is installed; the manifest is not yet.
	if err := os.WriteFile(filepath.Join(dir, "dek.key"), []byte("archive-dek.key"), 0600); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, restorejournal.FileName)
	if err := os.WriteFile(journal, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	err = verifyKeyFileSetConsistency(cfg)
	if err == nil || !strings.Contains(err.Error(), "admin restore --recover") || strings.Contains(err.Error(), "key-set manifest") {
		t.Fatalf("journal and mismatch: boot must refuse naming the journal and --recover only, got %v", err)
	}

	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	err = verifyKeyFileSetConsistency(cfg)
	if err == nil || !strings.Contains(err.Error(), "does not match the key-set manifest") || !strings.Contains(err.Error(), "dek.key") {
		t.Fatalf("mismatch without a journal: boot must still refuse, naming dek.key, got %v", err)
	}
}
