// recovery_key_startup_warn_test.go — coverage for warnIfRecoveryKeyMissing
// (F6, recovery-key visibility): the server must WARN on every boot while
// no recovery key is configured, so an operator sees it without having to
// run `admin diagnose` separately.
package main

import (
	"bytes"
	"context"
	"log"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRecoveryKeyWarnTestStore(t *testing.T) storage.Storage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	if err := db.AutoMigrate(&models.RecoveryKeyRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store.NewLocalStorage(db)
}

func captureLogOutput(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// TestWarnIfRecoveryKeyMissing_NoKeyWarns verifies the WARN fires (naming the
// fix command) when no recovery key has ever been generated.
func TestWarnIfRecoveryKeyMissing_NoKeyWarns(t *testing.T) {
	s := newRecoveryKeyWarnTestStore(t)
	out := captureLogOutput(func() { warnIfRecoveryKeyMissing(s) })

	if !bytes.Contains([]byte(out), []byte("WARNING")) {
		t.Fatalf("expected a WARNING log line, got: %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("recovery-key rotate")) {
		t.Fatalf("expected the WARNING to name the fix command, got: %q", out)
	}
}

// TestWarnIfRecoveryKeyMissing_KeyConfiguredSilent verifies NO warning is
// logged once a recovery key exists — no behavior change from today when a
// key is already configured.
func TestWarnIfRecoveryKeyMissing_KeyConfiguredSilent(t *testing.T) {
	s := newRecoveryKeyWarnTestStore(t)
	rec := &models.RecoveryKeyRecord{KeyHash: "x", KeyVersion: 1}
	if err := s.SetRecoveryKeyRecord(context.Background(), rec); err != nil {
		t.Fatalf("seed recovery key: %v", err)
	}

	out := captureLogOutput(func() { warnIfRecoveryKeyMissing(s) })

	if bytes.Contains([]byte(out), []byte("WARNING")) {
		t.Fatalf("expected no warning once a key is configured, got: %q", out)
	}
}
