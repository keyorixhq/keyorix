package deploy

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// HELM-NOTES-ADMIN (DEMO-WALK-4 finding 7): step 3 of NOTES.txt said "No admin
// password was set" for a release whose existing Secret carried
// KEYORIX_ADMIN_PASSWORD, and the server had in fact bootstrapped the admin on
// first start. The chart can only know the password exists from the values
// (auth.adminPassword, auth.existingSecretKeys.adminPassword) or a live `lookup`,
// which is empty under helm template, --dry-run and GitOps renderers. So the
// no-password branch must be true when the Secret does carry the key, and the
// manual-init command must read the Secret the release actually uses.
//
// Notes are only printed by `helm install`, so this renders with
// --dry-run=client (no cluster needed) and takes the text after "NOTES:".
// Skips when helm is not installed, like the other chart tests.
func TestHelmNotesAdminStep(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed -- skipping chart NOTES check")
	}
	chart := filepath.Join("..", "deploy", "helm", "keyorix")
	notes := func(t *testing.T, extra ...string) string {
		t.Helper()
		args := append([]string{"install", "kx", chart, "--dry-run=client", "--namespace", "kx-ns",
			"--set", "postgresql.auth.password=x"}, extra...)
		out, err := exec.Command("helm", args...).CombinedOutput() //nolint:gosec // fixed binary and chart path
		if err != nil {
			t.Fatalf("helm install --dry-run=client: %v\n%s", err, out)
		}
		_, after, ok := strings.Cut(string(out), "\nNOTES:\n")
		if !ok {
			t.Fatalf("no NOTES section in the dry-run output:\n%s", out)
		}
		return after
	}
	const falseClaim = "No admin password was set"
	const adminPw = "zq9-unrelated-long-value-77"

	t.Run("password in values: log in", func(t *testing.T) {
		n := notes(t, "--set", "auth.masterPassword=x", "--set", "auth.adminPassword="+adminPw)
		if !strings.Contains(n, "3. Log in with the admin you configured") {
			t.Errorf("step 3 should tell the user to log in:\n%s", n)
		}
		if strings.Contains(n, falseClaim) || strings.Contains(n, "initialise the first admin manually") {
			t.Errorf("a configured password must not get the manual-init instructions:\n%s", n)
		}
	})
	t.Run("existing Secret declared to carry the password: log in", func(t *testing.T) {
		n := notes(t, "--set", "auth.existingSecret=keyorix-auth", "--set", "auth.existingSecretKeys.adminPassword=true")
		if !strings.Contains(n, "3. Log in with the admin you configured") ||
			!strings.Contains(n, `"keyorix-auth" Secret`) {
			t.Errorf("step 3 should say to log in and name the Secret:\n%s", n)
		}
		if strings.Contains(n, falseClaim) {
			t.Errorf("must not claim no password was set:\n%s", n)
		}
	})
	t.Run("existing Secret the render cannot read: true either way", func(t *testing.T) {
		// This is the README quick start: the Secret has KEYORIX_ADMIN_PASSWORD, but
		// lookup returns nothing under a dry run, so the chart cannot know.
		n := notes(t, "--set", "auth.existingSecret=keyorix-auth")
		if strings.Contains(n, falseClaim) {
			t.Errorf("the render cannot know the Secret lacks the key, so it must not say %q:\n%s", falseClaim, n)
		}
		for _, want := range []string{
			"could not see an admin password",
			"If your Secret does carry KEYORIX_ADMIN_PASSWORD",
			"log in as auth.adminUsername=",
			"get secret keyorix-auth",
		} {
			if !strings.Contains(n, want) {
				t.Errorf("step 3 lacks %q (the manual-init token must come from the Secret the release uses):\n%s", want, n)
			}
		}
	})
	t.Run("chart-managed Secret without a password: manual init", func(t *testing.T) {
		n := notes(t, "--set", "auth.masterPassword=x")
		if strings.Contains(n, falseClaim) {
			t.Errorf("wording must be true for every no-password render:\n%s", n)
		}
		for _, want := range []string{"initialise the first admin manually", "get secret kx-keyorix "} {
			if !strings.Contains(n, want) {
				t.Errorf("step 3 lacks %q:\n%s", want, n)
			}
		}
	})
}
