package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// writeHexKEK writes a fresh random 32-byte KEK to path as hex (the FileKeyProvider
// accepts hex) and returns the path.
func writeHexKEK(t *testing.T, path string) {
	t.Helper()
	raw := make([]byte, crypto.KEKSize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("gen kek: %v", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)), 0600); err != nil {
		t.Fatalf("write kek: %v", err)
	}
}

func TestRewrapDEK_MigratesKEKWithoutChangingDEK(t *testing.T) {
	dir := t.TempDir()
	oldKEK := filepath.Join(dir, "old.kek")
	newKEK := filepath.Join(dir, "new.kek")
	writeHexKEK(t, oldKEK)
	writeHexKEK(t, newKEK)

	// Initialize under the OLD (file) provider — generates and wraps a DEK.
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(oldKEK))
	if err := km.Initialize(""); err != nil {
		t.Fatalf("initialize old: %v", err)
	}
	dekBefore := km.GetDEK()

	// Re-wrap under the NEW provider.
	if err := km.RewrapDEK(crypto.NewFileKeyProvider(newKEK)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if dekAfter := km.GetDEK(); !bytes.Equal(dekBefore, dekAfter) {
		t.Fatalf("DEK changed across re-wrap: before=%x after=%x", dekBefore, dekAfter)
	}

	// A fresh manager using the NEW provider must unwrap the SAME DEK from disk.
	kmNew := NewKeyManager(dir, "dek.key", "kek.salt")
	kmNew.SetKeyProvider(crypto.NewFileKeyProvider(newKEK))
	if err := kmNew.Initialize(""); err != nil {
		t.Fatalf("initialize new: %v", err)
	}
	if !bytes.Equal(kmNew.GetDEK(), dekBefore) {
		t.Fatalf("new provider unwrapped a different DEK")
	}

	// A fresh manager using the OLD provider must NO LONGER unwrap the DEK.
	kmOld := NewKeyManager(dir, "dek.key", "kek.salt")
	kmOld.SetKeyProvider(crypto.NewFileKeyProvider(oldKEK))
	if err := kmOld.Initialize(""); err == nil {
		t.Fatalf("old provider should fail to unwrap after migration, but succeeded")
	}
}

func TestRewrapDEK_RequiresInitializedManager(t *testing.T) {
	dir := t.TempDir()
	newKEK := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEK)

	km := NewKeyManager(dir, "dek.key", "kek.salt") // not Initialized — no DEK in memory
	if err := km.RewrapDEK(crypto.NewFileKeyProvider(newKEK)); err == nil {
		t.Fatalf("expected error re-wrapping an uninitialized manager")
	}
}

func TestRewrapDEK_FailingProviderLeavesActiveDEKIntact(t *testing.T) {
	dir := t.TempDir()
	oldKEK := filepath.Join(dir, "old.kek")
	writeHexKEK(t, oldKEK)

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(oldKEK))
	if err := km.Initialize(""); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	wrappedBefore, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	if err != nil {
		t.Fatalf("read dek: %v", err)
	}

	// A file provider pointing at a missing path fails in KEK() — before any write.
	bad := crypto.NewFileKeyProvider(filepath.Join(dir, "does-not-exist.kek"))
	if err := km.RewrapDEK(bad); err == nil {
		t.Fatalf("expected re-wrap to fail with a missing-key provider")
	}
	wrappedAfter, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	if err != nil {
		t.Fatalf("read dek after: %v", err)
	}
	if !bytes.Equal(wrappedBefore, wrappedAfter) {
		t.Fatalf("active wrapped DEK changed after a failed re-wrap")
	}
}
