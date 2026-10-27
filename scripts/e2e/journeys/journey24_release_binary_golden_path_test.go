//go:build e2e

// Package journeys, journey 24: the release-binary golden path (docs/demo/GOLDEN-PATH.md,
// "Without Docker", DEMO-1 2026-10-27), driven the way a new customer types it, with the
// SECURE defaults the other journeys switch off: no `admin init --dev`. TLS from the
// first start with the generated self-signed certificate (the CLI trusts it through
// KEYORIX_CA_FILE), every install secret generated into a 0600 file and passed by path
// (`admin generate-secrets`, KEYORIX_*_FILE), the first admin created through
// `keyorix system init`, require_mfa enforced until TOTP is enrolled through the CLI.
//
// Steps (GOLDEN-PATH numbering): 1 install + posture, 2 admin + MFA, 3 teams/projects,
// 4 least privilege through group roles, 5 the secret lifecycle, 6 a CI machine identity
// over the CLI, `keyorix run` and HTTP, 7 audit search/export/verify, 8 backup into a
// fresh host directory (and, on PostgreSQL, a fresh database) and restore. Runs on
// SQLite always and on PostgreSQL when KEYORIX_TEST_PG_DSN is set.
//
// Not covered here, on purpose: audit tamper detection (journey 3), recover-admin
// (journeys 16 and 20), the upgrade from a release (release-qa), the web UI
// (web/e2e/real). Every other journey starts its server with `admin init --dev`
// (harness.StartServer); this one is the only CLI journey on the TLS baseline.
package journeys

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

const (
	j24StripeV1 = "j24-sk-live-v1-4c1e"
	j24StripeV2 = "j24-sk-live-v2-9b7a"
	j24StripeV3 = "j24-sk-live-v3-e05d"
	j24DBValue  = "j24-pg-pass-v1-77f3"
	j24CDNValue = "j24-cdn-token-v1-2a90"
)

func TestJourney_ReleaseBinaryGoldenPath(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	t.Run("sqlite", func(t *testing.T) {
		j24Walk(t, serverBin, cliBin, "")
	})
	t.Run("postgres", func(t *testing.T) {
		base := os.Getenv("KEYORIX_TEST_PG_DSN")
		if base == "" {
			t.Skip("KEYORIX_TEST_PG_DSN not set -- the PostgreSQL leg needs a database")
		}
		j24Walk(t, serverBin, cliBin, base)
	})
}

// j24Install is one install directory and the server running from it.
type j24Install struct {
	t          *testing.T
	dir        string
	serverBin  string
	cliBin     string
	adminEnv   []string // env for `keyorix-server admin ...`
	url        string
	cmd        *exec.Cmd
	exited     chan struct{}
	httpClient *http.Client
}

// j24Walk is the whole golden path on one backend. pgBase is "" for SQLite.
func j24Walk(t *testing.T, serverBin, cliBin, pgBase string) {
	// ── 1. install: generate-secrets, init (secure baseline), keys, schema, posture ──
	in := &j24Install{t: t, dir: t.TempDir(), serverBin: serverBin, cliBin: cliBin}
	in.adminEnv = append(harness.BaseServerEnv(in.dir), "KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password")
	out := in.admin("generate-secrets")
	if !strings.Contains(out, "secrets/master_password") {
		t.Fatalf("generate-secrets did not report the master password file:\n%s", out)
	}
	if pgBase == "" {
		in.admin("init", "--config", "./keyorix.yaml")
	} else {
		in.admin("init", "--storage-type", "postgres", "--config", "./keyorix.yaml")
		j24UsePostgres(t, in, isolatedPGDatabase(t, pgBase, "j24_gp"))
		in.admin("init", "--config", "./keyorix.yaml")
	}
	cfg := in.read("keyorix.yaml")
	for _, want := range []string{"require_mfa: true", `cert_file: "certs/server.crt"`, `metrics_token_file: "secrets/metrics_token"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("admin init's config is not the secure baseline: no %q", want)
		}
	}
	in.admin("encryption", "init", "--config", "./keyorix.yaml")
	in.admin("migrate", "--config", "./keyorix.yaml")
	if pgBase == "" {
		// PostgreSQL in CI and in kpg has no TLS, which the posture rightly counts.
		if out := in.admin("validate", "--posture", "--config", "./keyorix.yaml"); !strings.Contains(out, "No deviations found.") {
			t.Fatalf("posture on a fresh secure install:\n%s", out)
		}
	}
	harness.RewritePort(t, in.dir, harness.FreeTCPPort(t))
	in.start(true)
	t.Cleanup(in.stop)

	if resp, err := http.Get(strings.Replace(in.url, "https://", "http://", 1) + "/health"); err == nil { // #nosec G107 -- fixed localhost test URL
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("plain HTTP /health answered 200 on a TLS-only server")
		}
	}

	// ── 2. first admin through the CLI, then MFA ──────────────────────────────────
	admin := in.cliEnv("h-admin")
	out = runCLI(t, cliBin, withEnv(admin,
		"KEYORIX_ADMIN_PASSWORD_FILE="+in.path("secrets/admin_password"),
		"KEYORIX_BOOTSTRAP_TOKEN_FILE="+in.path("secrets/bootstrap_token")),
		"system", "init", "--server", in.url, "--admin-username", "admin", "--admin-email", "admin@acme.example")
	if !strings.Contains(out, "initialised successfully") {
		t.Fatalf("system init:\n%s", out)
	}
	adminPw := in.path("secrets/admin_password")
	runCLI(t, cliBin, withEnv(admin, "KEYORIX_PASSWORD_FILE="+adminPw), "login", "--server", in.url, "--username", "admin")
	if out := runCLIExpectErr(t, cliBin, admin, "secret", "list"); !strings.Contains(out, "multi-factor") {
		t.Fatalf("secrets were reachable before MFA enrolment:\n%s", out)
	}
	adminTOTP, burned := j24EnrolTOTP(t, in, admin, adminPw)
	runCLI(t, cliBin, admin, "secret", "list")
	runCLI(t, cliBin, admin, "logout")
	if out := runCLIExpectErr(t, cliBin, withEnv(admin, "KEYORIX_PASSWORD_FILE="+adminPw), "login", "--server", in.url, "--username", "admin"); !strings.Contains(out, "second factor") {
		t.Fatalf("login without a code was not refused for the second factor:\n%s", out)
	}
	code, burned := totpCodeAfterStepN(t, adminTOTP, burned)
	runCLI(t, cliBin, withEnv(admin, "KEYORIX_PASSWORD_FILE="+adminPw, "KEYORIX_MFA_CODE="+code), "login", "--server", in.url, "--username", "admin")

	// ── 3. teams and projects ─────────────────────────────────────────────────────
	for _, p := range []string{"payments", "storefront", "data-platform"} {
		runCLI(t, cliBin, admin, "project", "create", "--name", p)
	}
	runCLI(t, cliBin, admin, "group", "create", "--name", "team-payments")
	runCLI(t, cliBin, admin, "group", "create", "--name", "team-storefront")

	// ── 4. people and roles, through groups ───────────────────────────────────────
	bobPw := in.writeSecret("bob.pw", "Harbor-Quill-58-Tundra!")
	carolPw := in.writeSecret("carol.pw", "Lantern-Moss-31-Cobalt!")
	runCLI(t, cliBin, withEnv(admin, "KEYORIX_INITIAL_PASSWORD_FILE="+bobPw), "user", "create", "--username", "bob", "--email", "bob@acme.example")
	runCLI(t, cliBin, withEnv(admin, "KEYORIX_INITIAL_PASSWORD_FILE="+carolPw), "user", "create", "--username", "carol", "--email", "carol@acme.example")
	runCLI(t, cliBin, admin, "group", "add-member", "team-payments", "--user", "bob")
	runCLI(t, cliBin, admin, "group", "add-member", "team-storefront", "--user", "carol")
	runCLI(t, cliBin, admin, "rbac", "assign-role-to-group", "--group", "team-payments", "--role", "project_developer", "--project", "payments")
	runCLI(t, cliBin, admin, "rbac", "assign-role-to-group", "--group", "team-storefront", "--role", "project_viewer", "--project", "storefront")
	runCLI(t, cliBin, admin, "rbac", "assign-role", "--user", "admin@acme.example", "--role", "project_admin", "--project", "payments")

	// ── 5. secrets: create, version, reveal, rotate, soft-delete, restore ────────────
	runCLISecret(t, cliBin, admin, j24StripeV1, "secret", "create", "--name", "stripe-api-key", "--project", "2", "--environment", "6")
	runCLISecret(t, cliBin, admin, j24DBValue, "secret", "create", "--name", "db-password", "--project", "2", "--environment", "6")
	runCLISecret(t, cliBin, admin, j24CDNValue, "secret", "create", "--name", "cdn-token", "--project", "3", "--environment", "9")
	runCLISecret(t, cliBin, admin, j24StripeV2, "secret", "update", "--id", "1")
	runCLIRotate(t, cliBin, admin, "1", j24StripeV3)
	if out := runCLI(t, cliBin, admin, "secret", "versions", "--id", "1"); !strings.Contains(out, "Total Versions: 3") {
		t.Fatalf("create + update + rotate should leave 3 versions:\n%s", out)
	}
	if got := parseDecryptedValue(t, runCLI(t, cliBin, admin, "secret", "get", "--id", "1", "--show-value")); got != j24StripeV3 {
		t.Fatalf("reveal after rotate = %q, want %q", got, j24StripeV3)
	}
	if out := runCLIWithStdinOK(t, cliBin, admin, "db-password\nyes\n", "secret", "delete", "--id", "2"); !strings.Contains(out, "soft-delete") {
		t.Fatalf("confirmed delete did not soft-delete:\n%s", out)
	}
	runCLIExpectErr(t, cliBin, admin, "secret", "get", "--id", "2", "--show-value")
	runCLI(t, cliBin, admin, "secret", "restore", "--id", "2")
	if got := parseDecryptedValue(t, runCLI(t, cliBin, admin, "secret", "get", "--id", "2", "--show-value")); got != j24DBValue {
		t.Fatalf("value after restore = %q, want %q", got, j24DBValue)
	}

	// ── 4b. least privilege: carol (storefront viewer), bob (payments developer) ───────
	carol := in.cliEnv("h-carol")
	runCLI(t, cliBin, withEnv(carol, "KEYORIX_PASSWORD_FILE="+carolPw), "login", "--server", in.url, "--username", "carol")
	j24EnrolTOTP(t, in, carol, carolPw)
	if out := runCLI(t, cliBin, carol, "project", "list"); !strings.Contains(out, "storefront") || strings.Contains(out, "payments") || strings.Contains(out, "data-platform") {
		t.Fatalf("carol should see exactly storefront:\n%s", out)
	}
	if got := parseDecryptedValue(t, runCLI(t, cliBin, carol, "secret", "get", "--id", "3", "--show-value")); got != j24CDNValue {
		t.Fatalf("carol reading her own project's secret = %q", got)
	}
	for _, denied := range [][]string{
		{"secret", "get", "--id", "1", "--show-value"},
		{"audit", "logs", "--limit", "1"},
		{"user", "list"},
	} {
		if out := runCLIExpectErr(t, cliBin, carol, denied...); !strings.Contains(out, "Insufficient permissions") {
			t.Fatalf("carol %v: want Insufficient permissions:\n%s", denied, out)
		}
	}
	runCLISecretExpectErr(t, cliBin, carol, "x", "secret", "update", "--id", "3")
	bob := in.cliEnv("h-bob")
	runCLI(t, cliBin, withEnv(bob, "KEYORIX_PASSWORD_FILE="+bobPw), "login", "--server", in.url, "--username", "bob")
	j24EnrolTOTP(t, in, bob, bobPw)
	runCLISecret(t, cliBin, bob, j24DBValue+"-bob", "secret", "update", "--id", "2")
	runCLIExpectErr(t, cliBin, bob, "secret", "get", "--id", "3", "--show-value")

	// ── 6. a CI machine identity: CLI, keyorix run, HTTP ───────────────────────────
	runCLI(t, cliBin, admin, "machine", "create", "--name", "payments-ci", "--project", "payments", "--type", "ci")
	runCLI(t, cliBin, admin, "machine", "grant-role", "payments-ci", "--project", "payments", "--role", "project_viewer")
	tokenFile := in.path("ci.token")
	runCLI(t, cliBin, admin, "machine", "token", "issue", "payments-ci", "--name", "ci", "--project", "payments", "--expires-in-days", "30", "--output-file", tokenFile)
	if fi, err := os.Stat(tokenFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("machine token file: %v, mode %v (want 0600)", err, fi)
	}
	ci := append(harness.BaseServerEnv(in.mkdir("h-ci")),
		"KEYORIX_SERVER="+in.url, "KEYORIX_TOKEN_FILE="+tokenFile, "KEYORIX_CA_FILE="+in.path("certs/server.crt"))
	if got := parseDecryptedValue(t, runCLI(t, cliBin, ci, "secret", "get", "--ref", "payments/production/stripe-api-key", "--show-value")); got != j24StripeV3 {
		t.Fatalf("CI read by ref = %q, want %q", got, j24StripeV3)
	}
	runCLI(t, cliBin, ci, "run", "--project", "payments", "--env", "production", "--var", "STRIPE_KEY=stripe-api-key",
		"--", "sh", "-c", `test "$STRIPE_KEY" = "`+j24StripeV3+`"`)
	if body := in.httpGet("/api/v1/secrets/1?include_value=true", in.read("ci.token"), http.StatusOK); !strings.Contains(body, j24StripeV3) {
		t.Fatalf("HTTP value read by the machine token did not return the value:\n%s", body)
	}
	in.httpGet("/api/v1/secrets/1?include_value=true", "", http.StatusUnauthorized)
	runCLIExpectErr(t, cliBin, ci, "secret", "get", "--id", "3", "--show-value")

	// ── 7. audit: the reveal, the machine read, the refusal; export; verify ──────────
	j24ExpectAudit(t, cliBin, admin, "User admin read secret stripe-api-key", "audit", "search", "--action", "secret.read", "--actor", "admin", "--limit", "100")
	j24ExpectAudit(t, cliBin, admin, "Machine identity payments-ci read secret stripe-api-key", "audit", "logs", "--actor-type", "machine_identity", "--limit", "100")
	j24ExpectAudit(t, cliBin, admin, "was refused a secret value read", "audit", "search", "--action", "secret.read", "--actor", "carol", "--limit", "100")
	exported := runCLI(t, cliBin, admin, "audit", "export", "--all")
	j24CheckExport(t, exported)
	j24ExpectAudit(t, cliBin, admin, "Audit chain: VALID", "audit", "verify")

	// ── 8. backup, then restore onto a fresh host directory ────────────────────────
	backup := filepath.Join(t.TempDir(), "keyorix-backup.tar.gz")
	if pgBase == "" {
		in.stop() // SQLite: admin backup needs the database to itself
	}
	if out := in.admin("backup", "--output", backup, "--config", "./keyorix.yaml"); !strings.Contains(out, "Backup written") {
		t.Fatalf("admin backup:\n%s", out)
	}
	in.stop()

	dr := &j24Install{t: t, dir: t.TempDir(), serverBin: serverBin, cliBin: cliBin}
	dr.adminEnv = append(harness.BaseServerEnv(dr.dir), "KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password")
	for _, f := range []string{"keyorix.yaml", "certs/server.crt", "certs/server.key", "secrets/master_password", "secrets/metrics_token"} {
		dr.copyFrom(in, f)
	}
	if pgBase != "" {
		dr.copyFrom(in, "secrets/db_password")
		dr.adminEnv = append(dr.adminEnv, "KEYORIX_DB_PASSWORD_FILE=secrets/db_password")
		fresh := parsePGDSN(t, isolatedPGDatabase(t, pgBase, "j24_dr"))
		cfg := dr.read("keyorix.yaml")
		cfg = regexp.MustCompile(`(?m)^    name: .*$`).ReplaceAllString(cfg, "    name: "+fresh.DBName)
		dr.write("keyorix.yaml", cfg)
	}
	if out := dr.admin("restore", "--input", backup, "--config", "./keyorix.yaml"); !strings.Contains(out, "verify-audit on the restored database: VALID") {
		t.Fatalf("admin restore did not end VALID:\n%s", out)
	}
	harness.RewritePort(t, dr.dir, harness.FreeTCPPort(t))
	dr.start(false)
	t.Cleanup(dr.stop)
	admin2 := dr.cliEnv("h-admin")
	code, _ = totpCodeAfterStepN(t, adminTOTP, burned)
	runCLI(t, cliBin, withEnv(admin2, "KEYORIX_PASSWORD_FILE="+adminPw, "KEYORIX_MFA_CODE="+code), "login", "--server", dr.url, "--username", "admin")
	if got := parseDecryptedValue(t, runCLI(t, cliBin, admin2, "secret", "get", "--id", "1", "--show-value")); got != j24StripeV3 {
		t.Fatalf("after restore, secret 1 = %q, want %q", got, j24StripeV3)
	}
	if out := runCLI(t, cliBin, admin2, "secret", "versions", "--id", "1"); !strings.Contains(out, "Total Versions: 3") {
		t.Fatalf("after restore, versions:\n%s", out)
	}
	j24ExpectAudit(t, cliBin, admin2, "Machine identity payments-ci read secret stripe-api-key", "audit", "logs", "--actor-type", "machine_identity", "--limit", "100")
	j24ExpectAudit(t, cliBin, admin2, "Audit chain: VALID", "audit", "verify")
}

// j24UsePostgres points a `--storage-type postgres` config at dsn the way the docs say:
// connection fields in the file, the password in a 0600 file named by
// KEYORIX_DB_PASSWORD_FILE.
func j24UsePostgres(t *testing.T, in *j24Install, dsn string) {
	c := parsePGDSN(t, dsn)
	cfg := in.read("keyorix.yaml")
	if !strings.Contains(cfg, "\n  database:\n") {
		t.Fatalf("postgres config has no storage.database block to fill")
	}
	in.write("keyorix.yaml", strings.Replace(cfg, "\n  database:\n", "\n  database:\n"+c.yaml(), 1))
	in.writeSecret("secrets/db_password", c.Password)
	in.adminEnv = append(in.adminEnv, "KEYORIX_DB_PASSWORD_FILE=secrets/db_password")
}

// j24EnrolTOTP runs `mfa enroll` + `mfa activate` as the logged-in user in env and
// returns the TOTP secret and the step its activation code burned.
func j24EnrolTOTP(t *testing.T, in *j24Install, env []string, pwFile string) (string, int64) {
	t.Helper()
	out := runCLI(t, in.cliBin, env, "mfa", "enroll")
	m := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{16,})\s*$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("mfa enroll printed no setup key:\n%s", out)
	}
	now := time.Now().UTC()
	out = runCLI(t, in.cliBin, withEnv(env, "KEYORIX_MFA_CODE="+totpCodeAt(t, m[1], now), "KEYORIX_PASSWORD_FILE="+pwFile), "mfa", "activate")
	if !strings.Contains(out, "MFA enabled") {
		t.Fatalf("mfa activate:\n%s", out)
	}
	return m[1], totpStep(now)
}

func j24ExpectAudit(t *testing.T, cliBin string, env []string, want string, args ...string) {
	t.Helper()
	if out := runCLI(t, cliBin, env, args...); !strings.Contains(out, want) {
		t.Fatalf("keyorix %s: no %q in\n%s", strings.Join(args, " "), want, out)
	}
}

// j24CheckExport: `audit export --all` is NDJSON, every line a chained event.
func j24CheckExport(t *testing.T, out string) {
	t.Helper()
	n := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue // the trailing "exported N event(s)" status line
		}
		var ev struct {
			ID        int64  `json:"id"`
			EntryHash string `json:"entry_hash"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.ID == 0 || ev.EntryHash == "" {
			t.Fatalf("audit export line is not a chained event (%v): %s", err, line)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("audit export returned %d events, want the whole walk (>= 20)", n)
	}
}

// ── install helpers ──────────────────────────────────────────────────────────────

func (in *j24Install) path(rel string) string { return filepath.Join(in.dir, rel) }

func (in *j24Install) mkdir(rel string) string {
	p := in.path(rel)
	if err := os.MkdirAll(p, 0o700); err != nil {
		in.t.Fatalf("mkdir %s: %v", p, err)
	}
	return p
}

func (in *j24Install) read(rel string) string {
	b, err := os.ReadFile(in.path(rel)) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		in.t.Fatalf("read %s: %v", rel, err)
	}
	return strings.TrimSpace(string(b))
}

func (in *j24Install) write(rel, content string) {
	if err := os.WriteFile(in.path(rel), []byte(content+"\n"), 0o600); err != nil { // #nosec G306 G703 -- t.TempDir() path
		in.t.Fatalf("write %s: %v", rel, err)
	}
}

func (in *j24Install) writeSecret(rel, value string) string {
	if err := os.MkdirAll(filepath.Dir(in.path(rel)), 0o700); err != nil {
		in.t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(in.path(rel), []byte(value), 0o600); err != nil { // #nosec G703 -- t.TempDir() path
		in.t.Fatalf("write %s: %v", rel, err)
	}
	return in.path(rel)
}

func (in *j24Install) copyFrom(src *j24Install, rel string) {
	b, err := os.ReadFile(src.path(rel)) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		in.t.Fatalf("copy %s: %v", rel, err)
	}
	in.mkdir(filepath.Dir(rel))
	if err := os.WriteFile(in.path(rel), b, 0o600); err != nil { // #nosec G703 -- t.TempDir() path
		in.t.Fatalf("copy %s: %v", rel, err)
	}
}

// admin runs `keyorix-server admin <args>` in the install directory and fails on error.
func (in *j24Install) admin(args ...string) string {
	in.t.Helper()
	out, err := harness.RunAdminCmd(in.serverBin, in.dir, in.adminEnv, args...)
	if err != nil {
		in.t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// cliEnv is an isolated CLI home that trusts this install's certificate.
func (in *j24Install) cliEnv(home string) []string {
	return append(harness.BaseServerEnv(in.mkdir(home)), "KEYORIX_CA_FILE="+in.path("certs/server.crt"))
}

// start runs the server from the install directory, as the docs do, and waits for
// /health over TLS to answer with this boot's nonce (not some other process's).
func (in *j24Install) start(bootstrap bool) {
	t := in.t
	t.Helper()
	port := regexp.MustCompile(`(?m)^    port: "(\d+)"`).FindStringSubmatch(in.read("keyorix.yaml"))
	if port == nil {
		t.Fatal("no HTTP port in keyorix.yaml")
	}
	in.url = "https://127.0.0.1:" + port[1]
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(in.read("certs/server.crt"))) {
		t.Fatal("certs/server.crt is not a PEM certificate")
	}
	in.httpClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	nonce := fmt.Sprintf("j24-%d", time.Now().UnixNano())
	env := append(append([]string{}, in.adminEnv...), "KEYORIX_CONFIG_PATH=./keyorix.yaml", "KEYORIX_E2E_INSTANCE_NONCE="+nonce)
	if bootstrap {
		env = append(env, "KEYORIX_BOOTSTRAP_TOKEN_FILE=secrets/bootstrap_token")
	}
	logFile, err := os.Create(in.path("server.log")) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("server log: %v", err)
	}
	in.cmd = exec.Command(in.serverBin) // #nosec G204 -- the binary this journey built nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e journey itself built; no external input reaches it
	in.cmd.Dir, in.cmd.Env, in.cmd.Stdout, in.cmd.Stderr = in.dir, env, logFile, logFile
	if err := in.cmd.Start(); err != nil {
		t.Fatalf("start keyorix-server: %v", err)
	}
	in.exited = make(chan struct{})
	go func() { _ = in.cmd.Wait(); _ = logFile.Close(); close(in.exited) }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-in.exited:
			t.Fatalf("keyorix-server exited during startup:\n%s", in.read("server.log"))
		default:
		}
		if resp, err := in.httpClient.Get(in.url + "/health"); err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if !strings.Contains(string(body), nonce) {
					t.Fatalf("a different server answers on %s (port race): %s", in.url, body)
				}
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("keyorix-server never became healthy over TLS:\n%s", in.read("server.log"))
}

// stop sends SIGTERM (a graceful shutdown, as an operator's service manager would)
// and waits for the process to exit. Safe to call twice.
func (in *j24Install) stop() {
	if in.cmd == nil || in.cmd.Process == nil {
		return
	}
	select {
	case <-in.exited:
		return
	default:
	}
	_ = in.cmd.Process.Signal(os.Interrupt)
	select {
	case <-in.exited:
	case <-time.After(20 * time.Second):
		_ = in.cmd.Process.Kill()
		<-in.exited
	}
}

// httpGet calls the API over TLS with an optional bearer token and checks the status.
func (in *j24Install) httpGet(path, token string, wantStatus int) string {
	t := in.t
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, in.url+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := in.httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s = %d, want %d: %s", path, resp.StatusCode, wantStatus, body)
	}
	return string(body)
}
