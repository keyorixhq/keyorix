//go:build e2e

// upgrade_test.go is I3: the "table missing on upgraded installs" class
// PR #2258 also warned about -- a fresh SQLite/Postgres database ISN'T the
// only "first time this code path runs" case. An install that was created
// by an OLDER release binary and then upgraded in place (new binary,
// existing database) exercises the migration path's "already-migrated,
// converge the diff" branches instead of its "create from nothing" ones --
// a structurally different code path (see internal/storage/factory.go's own
// tableExists-guarded blocks, most of which have separate fresh-vs-existing
// arms) that a fresh-database-only smoke run (upgrade_test.go's own sibling,
// api_smoke_test.go) never touches.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// defaultUpgradeFromReleaseTag is the release this test upgrades FROM:
// the last patch of the PREVIOUS minor, the one hop docs/UPGRADING.md §1a
// supports (a skipped minor is not supported before 1.0). The point is to
// catch "the last release's schema, migrated by HEAD," which is what a real
// operator upgrading one version at a time actually does. Move it forward
// when a new minor ships. Override via KEYORIX_E2E_UPGRADE_FROM_TAG for a
// manual run against a different release.
const defaultUpgradeFromReleaseTag = "v0.96.3"

// oldBinaryInitArgs returns the `admin init` arguments for the downloaded
// OLD binary. This harness drives plain HTTP, and a binary that has --dev
// (SECURE-DEFAULT-1) writes the TLS baseline without it, so pass --dev when
// `admin init --help` lists the flag (the same probe scripts/release-qa/
// scenario1.sh uses). A release that predates the flag already writes the
// relaxed config.
func oldBinaryInitArgs(t *testing.T, binary, dir string, env []string, configPath string) []string {
	t.Helper()
	help, err := harness.RunAdminCmd(binary, dir, env, "init", "--help")
	if err != nil {
		t.Fatalf("%s admin init --help: %v\n%s", filepath.Base(binary), err, help)
	}
	return initArgsForHelp(help, configPath)
}

// optOutRequireMFA rewrites the generated config's `require_mfa: true` to
// false and reports whether the line existed (a release that predates the
// key does not write it).
func optOutRequireMFA(t *testing.T, dir string) bool {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("read config before require_mfa opt-out: %v", err)
	}
	rewritten, ok := disableRequireMFA(string(raw))
	if !ok {
		t.Logf("old config has no require_mfa line; leaving it as generated")
		return false
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil { // #nosec G703 -- dir is always t.TempDir()
		t.Fatalf("write config with require_mfa: false: %v", err)
	}
	t.Logf("old config set require_mfa: true; opted this harness out (explicit false) so the old server's admin can create data without TOTP")
	return true
}

// disableRequireMFA flips an explicit `require_mfa: true` line to false.
func disableRequireMFA(cfg string) (string, bool) {
	const on, off = "\n  require_mfa: true\n", "\n  require_mfa: false\n"
	if !strings.Contains(cfg, on) {
		return cfg, false
	}
	return strings.Replace(cfg, on, off, 1), true
}

// initArgsForHelp builds the `admin init` arguments from that binary's own
// `admin init --help` text.
func initArgsForHelp(help, configPath string) []string {
	args := []string{"init"}
	if strings.Contains(help, "--dev") {
		args = append(args, "--dev")
	}
	return append(args, "--config", configPath)
}

// downloadReleaseBinary fetches the keyorix-server release binary for tag
// from GitHub's public release-asset URL (no auth needed for a public repo)
// and returns its local path, executable. Skips (not fails) the test on any
// download problem -- network unavailable, this GOOS/GOARCH combination has
// no published asset (e.g. Windows), or a bad tag -- since this test's whole
// premise depends on an external resource this driver does not control, the
// same "skip is not a failure" contract KEYORIX_TEST_PG_DSN-gated tests use
// elsewhere in this repo (see docs/security-closures.tsv's "pg-gated"
// verification column).
func downloadReleaseBinary(t *testing.T, tag string) string {
	t.Helper()
	url := fmt.Sprintf("https://github.com/keyorixhq/keyorix/releases/download/%s/keyorix-server_%s_%s",
		tag, runtime.GOOS, runtime.GOARCH)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url) // #nosec G107 -- fixed, versioned, publicly-documented release URL
	if err != nil {
		t.Skipf("could not reach %s (network unavailable?): %v", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Skipf("no release asset at %s (status %d) -- this GOOS/GOARCH combination may not be published for %s",
			url, resp.StatusCode, tag)
	}

	dir := t.TempDir() // under $TMPDIR, removed when the test ends
	binPath := filepath.Join(dir, "keyorix-server-old")
	out, err := os.Create(binPath) // #nosec G304 -- fixed tmpdir path this function itself created
	if err != nil {
		t.Fatalf("create %s: %v", binPath, err)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		t.Fatalf("download %s: %v", url, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", binPath, err)
	}
	if err := os.Chmod(binPath, 0o755); err != nil { // #nosec G302 -- must be executable
		t.Fatalf("chmod %s: %v", binPath, err)
	}
	return binPath
}

// TestAPISmoke_UpgradePath boots the OLD release binary, runs its own
// admin init/encryption init/migrate/boot/bootstrap sequence (creating a
// real admin, project, and secret under the OLD schema -- an upgraded
// install always has real pre-existing data, not just an empty schema),
// stops it, then runs `admin migrate` and boots the NEW (HEAD, built from
// this checkout) binary against that SAME on-disk database -- an in-place
// upgrade, exactly like a real operator's `systemctl stop keyorix &&
// <new binary> admin migrate && systemctl start keyorix`. The full
// create/read/list/update/delete sweep then runs against the upgraded
// server, logged in as the SAME admin account the OLD binary created --
// catching "table missing on an upgraded install" even for a table whose
// AutoMigrate guard only runs correctly on a fresh database (the exact
// shape of gap PR #2264 -- this session's own I2 finding -- specifically
// checked was NOT the case: see that PR's UpgradedInstall regression test).
func TestAPISmoke_UpgradePath(t *testing.T) {
	fromTag := os.Getenv("KEYORIX_E2E_UPGRADE_FROM_TAG")
	if fromTag == "" {
		fromTag = defaultUpgradeFromReleaseTag
	}
	oldBinary := downloadReleaseBinary(t, fromTag)
	newBinary, cliBin := harness.BuildBinaries(t)

	backend := harness.DBBackend{Name: "sqlite-upgrade-from-" + fromTag}
	dir := t.TempDir()
	env := append(harness.BaseServerEnv(dir),
		"KEYORIX_MASTER_PASSWORD=e2e-upgrade-master-password")
	configPath := "./keyorix.yaml"

	runAdmin := func(binary string, args ...string) {
		t.Helper()
		out, err := harness.RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("%s admin %v: %v\n%s", filepath.Base(binary), args, err, out)
		}
	}

	t.Logf("provisioning with OLD binary (%s, %s)", fromTag, oldBinary)
	runAdmin(oldBinary, oldBinaryInitArgs(t, oldBinary, dir, env, configPath)...)
	runAdmin(oldBinary, "encryption", "init", "--config", configPath)
	runAdmin(oldBinary, "migrate", "--config", configPath)

	// A release whose template writes require_mfa: true (v0.96.x) would confine
	// this harness's admin to MFA enrolment on the OLD server; opt out visibly,
	// as the fresh-install legs do (harness.Backend.NoMFAReason). An older
	// release (no such line) keeps its config as is.
	mfaOptedOut := optOutRequireMFA(t, dir)

	port := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, port)

	const bootstrapToken = "e2e-upgrade-bootstrap-token-0123456789"
	// The previous release predates /health's instance_nonce echo, so
	// WaitHealthy must confirm it via the old binary's access log (#2596).
	oldSrv := harness.BootAndBootstrap(t, oldBinary, dir, env, configPath, port, bootstrapToken,
		"upgradeadmin", "upgradeadmin@example.invalid", upgradeAdminPassword, harness.WithPreNonceBinary())

	// Real pre-existing data under the OLD schema: an operator's install
	// always has data by the time it's upgraded, not just an empty schema.
	oldClient := newClient(t, oldSrv.BaseURL)
	oldClient.login("upgradeadmin", upgradeAdminPassword)
	oldClient.callExpect("POST", "POST /api/v1/projects", "/api/v1/projects",
		map[string]string{"name": "e2e-upgrade-project"}, 200, 201)

	t.Log("stopping OLD binary")
	oldSrv.Close()
	// Give the OS a moment to release the SQLite file lock before the new
	// binary's subprocess admin commands touch the same DB file (same
	// precedent as server/admin_recover_admin_integration_test.go's
	// bootstrapAdminViaHTTP).
	time.Sleep(200 * time.Millisecond)

	t.Logf("upgrading with NEW (HEAD) binary")
	runAdmin(newBinary, "migrate", "--config", configPath)

	newPort := harness.FreeTCPPort(t)
	harness.RewritePort(t, dir, newPort)

	// The upgraded server serves /scim/v2 like the fresh-install legs do: the sweep below walks
	// every route.json route, SCIM included. The old release's config has no scim block.
	harness.EnableSCIMConfig(t, dir)
	scimToken := harness.NewSCIMToken(t)

	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, // unused post-bootstrap, harmless to still set
		"KEYORIX_CONFIG_PATH="+configPath,
		harness.SCIMTokenEnv+"="+scimToken,
	)
	newSrv := &harness.Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + newPort,
		Binary: newBinary, Env: serverEnv, LogPath: filepath.Join(dir, "e2e-upgrade-server.log"),
		Backend: backend, SCIMToken: scimToken,
	}
	harness.StartBackgroundProcess(t, newSrv, serverEnv)
	t.Cleanup(newSrv.Close)
	harness.WaitHealthy(t, newSrv)

	// ADR-112: if the old release's config never set security.require_mfa and
	// its database already has users, HEAD must boot it in the require_mfa grace
	// period (warning, not enforced) rather than confine the existing admin to MFA
	// enrolment -- the sweep below logs in as that admin without MFA. When the
	// old config set it (v0.96.x writes it; the harness turned it off), the
	// explicit value is honoured and there is no grace period to warn about.
	logBytes, err := os.ReadFile(newSrv.LogPath)
	if err != nil {
		t.Fatalf("read upgraded server log: %v", err)
	}
	hasGrace := strings.Contains(string(logBytes), "ADR-112 grace period: security.require_mfa")
	if !mfaOptedOut && !hasGrace {
		t.Fatalf("expected the ADR-112 require_mfa grace-period warning after upgrade; server log:\n%s", logBytes)
	}
	if mfaOptedOut && hasGrace {
		t.Fatalf("require_mfa was set explicitly in the old config but HEAD logged the grace-period warning; server log:\n%s", logBytes)
	}

	// The full happy-path sweep, logged in as the admin the OLD binary
	// created -- proves every route this driver covers works against a
	// database that started life under the previous release's schema, not
	// just a brand-new one.
	runAPISmokeAgainstServer(t, newSrv, cliBin, backend, "upgradeadmin", upgradeAdminPassword)
}

// upgradeAdminPassword shares no substring with "upgradeadmin"/its email/
// display name -- see harness.BootstrapAdminPassword for why that
// matters (internal/core/rules.DefaultPasswordPolicy).
const upgradeAdminPassword = "Meridian-Cobalt-19-Ferrous!"
