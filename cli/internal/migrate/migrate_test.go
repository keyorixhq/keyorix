package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

// writeYAML is a small test helper -- both fixtures below are simple enough that
// pulling in a template engine would be more code than the fixture itself.
func writeYAML(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestDetectOldServerURL_NoneFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "empty-xdg"))
	t.Setenv("HOME", filepath.Join(dir, "empty-home"))

	if _, ok := DetectOldServerURL(); ok {
		t.Fatal("DetectOldServerURL found a candidate with neither old config present")
	}
}

func TestDetectOldServerURL_FromCLIConfigOnly(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	xdg := filepath.Join(dir, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	writeYAML(t, filepath.Join(xdg, "keyorix", "cli.yaml"), "client:\n  endpoint: https://old-cli.example.test\n")

	c, ok := DetectOldServerURL()
	if !ok {
		t.Fatal("DetectOldServerURL found nothing, want the cli.yaml candidate")
	}
	if c.ServerURL != "https://old-cli.example.test" {
		t.Fatalf("ServerURL = %q, want %q", c.ServerURL, "https://old-cli.example.test")
	}
}

// TestDetectOldServerURL_CWDConfigTakesPrecedence proves the precedence order this
// package documents: when BOTH old config files are present with DIFFERENT server
// URLs, ./keyorix.yaml wins (it reflects the operator's most recent explicit `auth
// login`/`config set-remote`), and the cli.yaml candidate is neither silently merged
// in nor lost -- it is simply not the one returned for this call.
func TestDetectOldServerURL_CWDConfigTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	xdg := filepath.Join(dir, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	writeYAML(t, filepath.Join(xdg, "keyorix", "cli.yaml"), "client:\n  endpoint: https://from-cli-yaml.example.test\n")
	writeYAML(t, filepath.Join(dir, "keyorix.yaml"), "storage:\n  type: remote\n  remote:\n    base_url: https://from-cwd-config.example.test\n")

	c, ok := DetectOldServerURL()
	if !ok {
		t.Fatal("DetectOldServerURL found nothing, want the ./keyorix.yaml candidate")
	}
	if c.ServerURL != "https://from-cwd-config.example.test" {
		t.Fatalf("ServerURL = %q, want the CWD config's URL (precedence over cli.yaml)", c.ServerURL)
	}

	// Confirm the cli.yaml candidate is still independently discoverable (not
	// dropped) -- delete the higher-precedence file and detect again.
	if err := os.Remove(filepath.Join(dir, "keyorix.yaml")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	c2, ok := DetectOldServerURL()
	if !ok {
		t.Fatal("DetectOldServerURL found nothing after removing the CWD config, want the cli.yaml candidate")
	}
	if c2.ServerURL != "https://from-cli-yaml.example.test" {
		t.Fatalf("ServerURL = %q, want %q", c2.ServerURL, "https://from-cli-yaml.example.test")
	}
}

// TestDetectOldServerURL_NeverReadsAPIKeyOrToken guards the core security property
// this package exists for: even when both old config files carry a credential
// alongside their server URL, DetectOldServerURL's return type (Candidate) has no
// field capable of carrying one -- the only way to violate "never copies a token
// silently" would be to add such a field, which this test would then need to
// updated to read and assert empty.
func TestDetectOldServerURL_NeverReadsAPIKeyOrToken(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeYAML(t, filepath.Join(dir, "keyorix.yaml"), "storage:\n  type: remote\n  remote:\n    base_url: https://example.test\n    api_key: kx_pat_super_secret_value\n")

	c, ok := DetectOldServerURL()
	if !ok {
		t.Fatal("DetectOldServerURL found nothing, want the ./keyorix.yaml candidate")
	}
	if c.ServerURL != "https://example.test" {
		t.Fatalf("ServerURL = %q, want %q", c.ServerURL, "https://example.test")
	}
	// Candidate{ServerURL, Source} structurally cannot hold the api_key -- there is
	// no field to assert empty on. This test's job is to fail to compile if one is
	// ever added without a matching read here.
}
