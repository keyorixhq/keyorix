package configspace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestCanaryAsTopLevelKeyIsNotALeak drives the real loader with the canary as an unknown
// top-level key, the shape CI run 43424626656 (shard 5) flagged. TestLeaksCanary covers the
// oracle on hand-written texts; this one proves the loader's real message is tolerated.
func TestCanaryAsTopLevelKeyIsNotALeak(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keyorix.yaml")
	if err := os.WriteFile(p, []byte(fuzzCanary+": 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(p)
	if err == nil {
		t.Fatal("unknown top-level key was accepted")
	}
	if leaksCanary("load: " + err.Error()) {
		t.Fatalf("echoed key name flagged as a value leak: %v", err)
	}
}
