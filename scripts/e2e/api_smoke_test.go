//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestAPISmoke_SQLite is I2: boot a real keyorix-server against a freshly
// migrated SQLite database, bootstrap an admin, exercise one happy-path
// create/read/list/update/delete per feature group over the public REST API,
// assert no 5xx anywhere, assert every route.json route is exercised or
// explicitly skipped-with-reason, and verify the audit hash chain at the end.
func TestAPISmoke_SQLite(t *testing.T) {
	serverBin, cliBin := buildBinaries(t)
	backend := dbBackend{name: "sqlite"} // admin init's own default (configs/keyorix.yaml.tpl)
	runAPISmoke(t, serverBin, cliBin, backend)
}

// TestAPISmoke_Postgres is the same smoke run against PostgreSQL
// (docker postgres:16), gated on KEYORIX_TEST_PG_DSN exactly like this
// repo's existing pg-gated tests (see docs/security-closures.tsv's
// "pg-gated" verification column) -- skip, not fail, when no DSN is set.
func TestAPISmoke_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the PostgreSQL leg (see docker command in scripts/e2e's package doc / docs/TESTING_GUIDE.md)")
	}
	dbPassword := os.Getenv("KEYORIX_TEST_PG_PASSWORD")
	if dbPassword == "" {
		dbPassword = "keyorix-e2e-smoke"
	}
	serverBin, cliBin := buildBinaries(t)
	backend := dbBackend{
		name: "postgres",
		// Field-by-field form (configs/dev.yaml's own shape) rather than a
		// bare dsn: line, so KEYORIX_DB_PASSWORD stays out of the config
		// file entirely, matching this repo's own "credentials never in the
		// committed config" convention (configs/dev.yaml's header comment).
		configExtra: fmt.Sprintf("storage:\n  type: postgres\n  database:\n%s\n  encryption:\n    enabled: true\n    dek_path: keys/dek.key\n    salt_path: keys/kek.salt\n", pgDatabaseYAML(dsn)),
		extraEnv:    []string{"KEYORIX_DB_PASSWORD=" + dbPassword},
		verifyAuditFlag: func(_ string) []string {
			return []string{"--pg-dsn", dsn}
		},
	}
	runAPISmoke(t, serverBin, cliBin, backend)
}

// pgDatabaseYAML renders the storage.database.* block from a libpq-style DSN
// (host=... user=... dbname=... port=... password=... sslmode=...), leaving
// out password (see the KEYORIX_DB_PASSWORD env comment above). Deliberately
// minimal: this smoke driver only needs to reach a docker postgres:16
// instance, not represent every DSN shape a real deployment might use.
func pgDatabaseYAML(dsn string) string {
	fields := parseLibpqDSN(dsn)
	host := fields["host"]
	if host == "" {
		host = "localhost"
	}
	port := fields["port"]
	if port == "" {
		port = "5432"
	}
	name := fields["dbname"]
	if name == "" {
		name = "keyorix"
	}
	user := fields["user"]
	if user == "" {
		user = "keyorix"
	}
	sslMode := fields["sslmode"]
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf("    host: %s\n    port: \"%s\"\n    name: %s\n    user: %s\n    ssl_mode: %s\n",
		host, port, name, user, sslMode)
}

func runAPISmoke(t *testing.T, serverBin, cliBin string, backend dbBackend) {
	t.Helper()
	srv := startServer(t, serverBin, backend)
	t.Cleanup(srv.Close)
	runAPISmokeAgainstServer(t, srv, cliBin, backend, "smoketestadmin", bootstrapAdminPassword)
}

// runAPISmokeAgainstServer is runAPISmoke's group-running half, split out so
// I3's upgrade-path test (upgrade_test.go) can reuse the exact same
// create/read/list/update/delete sweep and coverage/audit assertions against
// a server it started its own way (an old-release binary's DB, migrated and
// booted with the HEAD binary) instead of a freshly-`startServer`-built one.
// adminUsername/adminPassword let the upgrade-path caller log in as the
// admin IT already bootstrapped with the OLD binary, rather than this
// function bootstrapping a new one.
func runAPISmokeAgainstServer(t *testing.T, srv *server, cliBin string, backend dbBackend, adminUsername, adminPassword string) {
	t.Helper()
	routes := loadRoutes(t)

	c := newClient(t, srv.baseURL)
	c.login(adminUsername, adminPassword)

	// Each groupXxx function drives one feature group's happy-path
	// create/read/list/update/delete (or as close to that as the feature
	// shape allows -- some are read-only, some are single-object, noted in
	// each function's own doc comment). Grouped into files by the research
	// clusters this driver was built from (groups_catalog.go, groups_identity.go,
	// groups_observability.go, groups_ops.go) purely for readability -- there
	// is no dependency ordering requirement between them beyond what's noted
	// inline (e.g. groupSecrets must run before groupShares, which shares the
	// secret it created).
	ctx := &smokeCtx{
		t: t, c: c, cli: cliBin, cliEnv: srv.cliEnv(),
		adminUsername: adminUsername, adminPassword: adminPassword,
	}

	groupAuthProfile(ctx)
	groupProjectsAndEnvironments(ctx)
	groupSecretsAndFolders(ctx)
	groupCLISmoke(ctx)
	groupSecretTemplates(ctx)
	groupSecretAccessRequests(ctx)
	groupUsersRolesRBAC(ctx)
	groupGroups(ctx)
	groupPermissions(ctx)
	groupNotifications(ctx)
	groupNotificationChannels(ctx)
	groupAlertEscalationPolicies(ctx)
	groupAudit(ctx)
	groupDashboard(ctx)
	groupSoD(ctx)
	groupCompliance(ctx)
	groupLicense(ctx)
	groupMachineIdentities(ctx)
	groupShares(ctx)
	groupRotationPolicies(ctx)
	groupDynamicSecrets(ctx)
	groupAccessRequests(ctx)
	groupRiskExceptions(ctx)
	groupLegalHold(ctx)
	groupInvitations(ctx)
	groupAdminAndSystem(ctx)

	// POST /auth/refresh and /auth/logout run last, deliberately outside any
	// group function: refresh ROTATES this driver's own bearer token (the old
	// one is evicted from the auth cache immediately -- server/http/handlers/
	// auth.go's RefreshToken), and logout ends the session this entire run
	// has depended on for every earlier authenticated call -- neither is safe
	// to run before groupAdminAndSystem's own cleanup. Capture and swap in
	// the newly-issued token before calling logout: calling logout with the
	// now-stale pre-refresh token 500s (Logout blanket-maps "session not
	// found" to 500 the same class of gap this session's other fixes
	// address), which is a real but separate finding not worth a further fix
	// PR here -- a real client always uses the token refresh just returned.
	refreshResp := c.callExpect("POST", "POST /auth/refresh", "/auth/refresh", nil, 200)
	var refreshed struct {
		Token string `json:"token"`
	}
	c.unmarshalData(refreshResp, &refreshed, "refresh token")
	if refreshed.Token != "" {
		c.token = refreshed.Token
	}
	c.callExpect("POST", "POST /auth/logout", "/auth/logout", nil, 200)

	assertRouteCoverage(t, routes, c)

	verifyAuditChain(t, srv, backend)
}

// cliEnv returns the environment a `keyorix` CLI invocation needs to talk to
// this running server: isolated HOME (so it never touches a real
// ~/.keyorix/cli.yaml -- see the repo's own "Local ~/.keyorix/cli.yaml breaks
// CLI tests" lesson) plus PATH.
func (s *server) cliEnv() []string {
	return []string{"HOME=" + s.dir, "PATH=" + os.Getenv("PATH")}
}

// smokeCtx bundles what every groupXxx function needs: the test handle, the
// authenticated API client, and the CLI binary + env for the "and the thin
// CLI where a command exists" half of I2. Shared, mutable scratch fields
// (created project/environment/secret IDs) let later groups build on earlier
// ones exactly like scripts/smoke.sh's own sequential flow does.
type smokeCtx struct {
	t      *testing.T
	c      *client
	cli    string
	cliEnv []string

	// adminUsername/adminPassword are the CLI-login credentials for the
	// account this run bootstrapped as admin -- "smoketestadmin" for a fresh
	// install (runAPISmoke), or whatever account the OLD binary created for
	// TestAPISmoke_UpgradePath. groupCLISmoke uses these rather than a
	// hardcoded literal so it works against either.
	adminUsername string
	adminPassword string

	adminUserID   uint
	projectID     uint
	environmentID uint
	secretID      uint
	secretValue   string
	userID        uint
	roleID        uint
}

// runCLI shells out to the built `keyorix` CLI binary against this smoke
// run's server, exactly like scripts/smoke.sh does -- the "thin CLI where a
// command exists" half of I2's brief. Fails the test on a non-zero exit.
func (ctx *smokeCtx) runCLI(args ...string) string {
	ctx.t.Helper()
	cmd := exec.Command(ctx.cli, args...)
	cmd.Env = ctx.cliEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		ctx.t.Fatalf("keyorix %v: %v\n%s", args, err, out)
	}
	return string(out)
}
