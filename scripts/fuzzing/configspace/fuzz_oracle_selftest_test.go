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

// TestConfigspaceI4_SecretFieldRedGreen proves that secretCanaryLoaded is not vacuous:
// a canary in a secret-typed field (server.http.metrics_token) is detected (red), and a
// canary only in a non-secret enum field (storage.type) is not (green).
// This guards the oracle fix that prevents false alarms when Validate echoes a non-secret
// field value (such as an invalid storage type) in its error message.
func TestConfigspaceI4_SecretFieldRedGreen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.yaml")

	// GREEN: canary placed into storage.type (a non-secret enum) — Validate echoes
	// it in the error, but it must not be flagged because storage.type is not secret.
	if err := os.WriteFile(p, []byte("storage:\n  type: "+fuzzCanary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgNonSecret, err := config.Load(p)
	if err != nil {
		t.Fatalf("setup (non-secret): Load failed: %v", err)
	}
	if cfgNonSecret.Storage.Type == "" {
		cfgNonSecret.Storage.Type = "local"
	}
	verr := cfgNonSecret.Validate()
	if verr == nil {
		t.Fatal("setup (non-secret): expected Validate to reject unknown storage type")
	}
	verdict := "validate: " + verr.Error()
	if !leaksCanary(verdict) {
		t.Fatal("setup (non-secret): Validate did not echo the canary (test premise broken)")
	}
	if secretCanaryLoaded(cfgNonSecret) {
		t.Fatal("green: storage.type canary falsely classified as a secret-field canary")
	}
	// Combined check as used in FuzzConfigLoadValidate: must not fire.
	if leaksCanary(verdict) && secretCanaryLoaded(cfgNonSecret) {
		t.Fatal("green: false alarm would still be reported for the non-secret enum echo")
	}

	// RED: canary placed into server.http.metrics_token (a secret-typed field).
	// A Validate that echoes a secret VALUE must be flagged.
	if err := os.WriteFile(p, []byte("server:\n  http:\n    metrics_token: "+fuzzCanary+"\nstorage:\n  type: sqlite\n  database:\n    path: k.db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgSecret, loadErr := config.Load(p)
	if loadErr != nil {
		t.Fatalf("setup (secret): Load failed: %v", loadErr)
	}
	if !secretCanaryLoaded(cfgSecret) {
		t.Fatal("red: metrics_token canary not detected as a secret-field canary — oracle is vacuous")
	}
	// Simulate a Validate that leaks the secret value in an error.
	fakeSecretError := "validate: metrics_token " + fuzzCanary + " is misconfigured"
	if !leaksCanary(fakeSecretError) {
		t.Fatal("red setup: fake secret error did not trigger leaksCanary (test premise broken)")
	}
	if !(leaksCanary(fakeSecretError) && secretCanaryLoaded(cfgSecret)) {
		t.Fatal("red: a secret VALUE echo must be flagged but combined check returned false")
	}
}
