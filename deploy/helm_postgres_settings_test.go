package deploy

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// postgresql.settings (DB-TUNE-1) renders extra `postgres -c key=value` args for
// the bundled PostgreSQL, keeps the secureBaseline TLS args, and refuses any
// value that turns commit durability off: the audit row is committed before a
// secret is returned, so synchronous_commit, fsync and full_page_writes stay
// on whatever the values say. Checks the RENDERED Deployment; skips when helm
// is not installed, like the other chart tests (CI's chart jobs have it).
func TestHelmPostgresSettings(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart postgresql.settings check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	render := func(sets ...string) (string, error) {
		args := []string{"template", "kx", chart, "-s", "templates/postgresql.yaml",
			"--set", "auth.masterPassword=x", "--set", "postgresql.auth.password=x"}
		for _, s := range sets {
			args = append(args, "--set-string", s)
		}
		out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
		return string(out), err
	}

	out, err := render()
	if err != nil {
		t.Fatalf("helm template (defaults): %v\n%s", err, out)
	}
	if strings.Contains(out, "postgresql.settings") || !strings.Contains(out, "- ssl=on") {
		t.Fatalf("default render must keep only the secureBaseline args:\n%s", out)
	}

	out, err = render("postgresql.settings.shared_buffers=256MB", "postgresql.settings.wal_compression=lz4", "postgresql.settings.synchronous_commit=on")
	if err != nil {
		t.Fatalf("helm template (profile): %v\n%s", err, out)
	}
	for _, want := range []string{`- "shared_buffers=256MB"`, `- "wal_compression=lz4"`, `- "synchronous_commit=on"`, "- ssl=on"} {
		if !strings.Contains(out, want) {
			t.Errorf("profile render is missing %s:\n%s", want, out)
		}
	}

	for _, bad := range []string{
		"postgresql.settings.synchronous_commit=off",
		"postgresql.settings.fsync=off",
		"postgresql.settings.fsync=false",
		"postgresql.settings.full_page_writes=OFF",
		"postgresql.settings.bad\\;key=1",
	} {
		if out, err := render(bad); err == nil {
			t.Errorf("--set-string %s must refuse to render, got:\n%s", bad, out)
		}
	}
}
