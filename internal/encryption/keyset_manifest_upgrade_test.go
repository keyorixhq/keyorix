package encryption

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The upgrade path for an existing install (#2900 criteria 2 and 4): a
// pre-manifest install with a password KEK and a Shamir fallback whose shares
// are six months old. Its first start on this version adopts the set (WARN +
// one audit event); a rotate-kek then rewrites only the salt and the DEK; the
// next start boots without adopting anything and without refusing the old
// shares — the false refusal #2462 had to fix must not come back.
func TestUpgrade_PreManifestInstallWithOldFallback_AdoptsThenSurvivesRotateKEK(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"share-1.hex", "share-2.hex"} {
		if err := os.WriteFile(filepath.Join(dir, "keys", s), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := passwordEncConfig()
	cfg.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir", ShamirShareFiles: []string{"keys/share-1.hex", "keys/share-2.hex"}}}
	open := func(pass string) *Service {
		t.Helper()
		svc := NewService(cfg, dir)
		svc.keyManager.SetKeyProvider(crypto.NewPasswordKeyProvider(pass, dir, "keys/kek.salt"))
		return svc
	}
	var mu sync.Mutex
	var events []string
	sink := func(_ context.Context, e *models.AuditEvent) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e.EventType)
		return nil
	}
	takeEvents := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := events
		events = nil
		return out
	}

	// The install as an older binary left it: keys, no manifest, old shares.
	install := open("old-pass")
	if err := install.keyManager.Initialize("old-pass"); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "keys", keyfiles.ManifestFileName)
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-180 * 24 * time.Hour)
	for _, s := range []string{"share-1.hex", "share-2.hex"} {
		if err := os.Chtimes(filepath.Join(dir, "keys", s), old, old); err != nil {
			t.Fatal(err)
		}
	}

	// First start on this version: adopted, one audit event.
	if err := keyfiles.VerifyKeySetConsistency(cfg, dir); err != nil {
		t.Fatalf("boot refusal on a pre-manifest install: %v", err)
	}
	boot := open("old-pass")
	boot.SetAuditSink(sink)
	if err := boot.ReconcileKeySet(); err != nil {
		t.Fatalf("ReconcileKeySet on a pre-manifest install: %v", err)
	}
	if got := takeEvents(); len(got) != 1 || got[0] != EventKeySetManifestAdopted {
		t.Fatalf("audit events on the first start = %v, want one %s", got, EventKeySetManifestAdopted)
	}
	if err := boot.keyManager.Initialize("old-pass"); err != nil {
		t.Fatalf("Initialize after adoption: %v", err)
	}

	// rotate-kek: salt and DEK only.
	if err := boot.keyManager.RotateKEKPassphrase("old-pass", "new-pass"); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}

	// Next start: no refusal, no adoption, the new passphrase opens the set.
	if err := keyfiles.VerifyKeySetConsistency(cfg, dir); err != nil {
		t.Fatalf("boot refusal after rotate-kek with a six-month-old fallback: %v", err)
	}
	next := open("new-pass")
	next.SetAuditSink(sink)
	if err := next.ReconcileKeySet(); err != nil {
		t.Fatalf("ReconcileKeySet after rotate-kek: %v", err)
	}
	if got := takeEvents(); len(got) != 0 {
		t.Fatalf("audit events after rotate-kek = %v, want none", got)
	}
	if err := next.keyManager.Initialize("new-pass"); err != nil {
		t.Fatalf("the new passphrase must open the set after rotate-kek: %v", err)
	}
	m, err := keyfiles.LoadManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if e := m.Files["share-1.hex"]; e.Operation != keyfiles.OpAdopted || e.Generation != 1 {
		t.Errorf("the fallback share must keep its adopted generation-1 entry, got %+v", e)
	}
	if e := m.Files["kek.salt"]; e.Operation != keyfiles.OpRotateKEK || e.Generation != 2 {
		t.Errorf("the salt must be at the rotate-kek generation, got %+v", e)
	}
}
