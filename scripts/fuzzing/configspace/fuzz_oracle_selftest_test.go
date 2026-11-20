package configspace

import (
	"os"
	"path/filepath"
	"strings"
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

// loadAndValidate runs the fuzz target's load step on doc: the verdict, and whether
// config.Load returned a config.
func loadAndValidate(t *testing.T, doc string) (verdict string, cfg *config.Config) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		return "load: " + err.Error(), nil
	}
	if c.Storage.Type == "" {
		c.Storage.Type = "local"
	}
	if err := c.Validate(); err != nil {
		return "validate: " + err.Error(), c
	}
	return "", c
}

// TestConfigspaceI4_NonSecretEnumEchoIsNotALeak is the KFZ-2026-167 green case: Validate
// echoes a canary the document put only into storage.type (a non-secret enum).
func TestConfigspaceI4_NonSecretEnumEchoIsNotALeak(t *testing.T) {
	doc := "storage:\n  type: " + fuzzCanary + "\n"
	verdict, cfg := loadAndValidate(t, doc)
	if cfg == nil || !leaksCanary(verdict) {
		t.Fatalf("premise: want a Validate error echoing the canary, got %q (loaded %v)", verdict, cfg != nil)
	}
	if i4Leak(verdict, []byte(doc), true) {
		t.Fatalf("storage.type echo flagged as a secret leak: %s", verdict)
	}
}

// TestConfigspaceI4_FailsClosed pins every case the KFZ-2026-167 exemption must not reach
// (REVIEW-4541 MEDIUM-1, probes P1-P3). Each was unflagged by the previous
// secretCanaryLoaded(cfg) gate.
func TestConfigspaceI4_FailsClosed(t *testing.T) {
	nonSecretDoc := []byte("storage:\n  type: " + fuzzCanary + "\n")
	cases := []struct {
		name    string
		verdict string
		data    []byte
		loaded  bool
	}{
		// P1: a load error has no cfg; nothing proves its echo is not a secret value.
		{"load error echo", "load: failed to unmarshal config: server.http.metrics_token " + fuzzCanary, []byte("server:\n  http:\n    metrics_token: " + fuzzCanary + "\n"), false},
		{"load error echo, canary only in a non-secret key", "load: bad storage.type " + fuzzCanary, nonSecretDoc, false},
		// P2: an env-sourced secret never sits in the document.
		{"env secret echo", "validate: storage.database.password " + envCanary + " rejected", []byte("storage:\n  type: postgres\n"), true},
		{"env secret echo next to a non-secret canary", "validate: invalid storage.type \"" + fuzzCanary + "\" (" + envCanary + ")", nonSecretDoc, true},
		// P3: a secret inside a sequence element (the harness's own sso seed).
		{"slice secret echo", "validate: sso provider okta: client_secret " + fuzzCanary, []byte(fuzzSeeds[6]), true},
		{"alias into a secret", "validate: token " + fuzzCanary, []byte("environment: &a " + fuzzCanary + "\nscim:\n  token: *a\n"), true},
		{"secret in a later document", "validate: x " + fuzzCanary, []byte("storage:\n  type: x\n---\nscim:\n  token: " + fuzzCanary + "\n"), true},
		{"undecodable document", "validate: x " + fuzzCanary, []byte("a: [\n"), true},
	}
	for _, c := range cases {
		if !i4Leak(c.verdict, c.data, c.loaded) {
			t.Errorf("%s: not flagged: %s", c.name, c.verdict)
		}
	}
	if i4Leak("validate: invalid storage.type \"x\"", nonSecretDoc, true) {
		t.Error("an error without a canary was flagged")
	}
}

// TestConfigspaceI4_EnvSecretReachesAccessor proves the env case above is the harness's
// real shape: the env canary is what GetPassword resolves to, with nothing in the document.
func TestConfigspaceI4_EnvSecretReachesAccessor(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", envCanary)
	_, cfg := loadAndValidate(t, "storage:\n  type: postgres\n")
	if cfg == nil {
		t.Fatal("premise: config did not load")
	}
	if got := cfg.Storage.Database.GetPassword(); got != envCanary {
		t.Fatalf("premise: GetPassword = %q, want the env canary", got)
	}
	if !i4Leak("validate: password "+cfg.Storage.Database.GetPassword(), []byte("storage:\n  type: postgres\n"), true) {
		t.Fatal("echo of an env-sourced secret not flagged")
	}
}

// TestConfigspaceI4_SliceSecretSeedIsSecret proves the sso seed really carries the canary
// in a sequence element's client_secret, the path the old gate could not see.
func TestConfigspaceI4_SliceSecretSeedIsSecret(t *testing.T) {
	_, cfg := loadAndValidate(t, fuzzSeeds[6])
	if cfg == nil || len(cfg.SSO.Providers) == 0 || cfg.SSO.Providers[0].ClientSecret != fuzzCanary {
		t.Fatal("premise: fuzzSeeds[6] no longer puts the canary into sso.providers[0].client_secret")
	}
	if !secretCanaryInDoc([]byte(fuzzSeeds[6])) {
		t.Fatal("sso.providers[].client_secret canary not seen")
	}
}

// TestLeaksCanary_JoinedConstructErrors drives the real loader into several "; "-joined
// construct errors and plants a value echo between two key echoes (REVIEW-4541 LOW-2): the
// key mask must stop at "; " and leave the value echo visible.
func TestLeaksCanary_JoinedConstructErrors(t *testing.T) {
	verdict, cfg := loadAndValidate(t, "a b: 1\nsecurity:\n  login_lockout:\n    max_attempts: "+fuzzCanary+"\nc d: 1\n")
	if cfg != nil || strings.Count(verdict, "; ") < 2 || strings.Count(verdict, "not found in type") < 2 {
		t.Fatalf("premise: want three joined construct errors, got %q", verdict)
	}
	if leaksCanary(verdict) {
		t.Fatalf("real loader output flagged: %s", verdict)
	}
	first, _, _ := strings.Cut(verdict, "; ")
	_, last, _ := strings.Cut(verdict[len(first)+2:], "; ")
	planted := first + "; line 4: cannot construct !!str `" + fuzzCanary + "` into int; " + last
	if !leaksCanary(planted) {
		t.Fatalf("value echo between two key echoes masked: %s", planted)
	}
}
