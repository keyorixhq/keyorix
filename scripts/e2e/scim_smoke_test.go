//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestAPISmoke_SCIMOnly_SQLite runs groupSCIM alone against a fresh SQLite server and checks
// that it reaches every /scim/v2 route in routes.json. The full sweep (TestAPISmoke_SQLite)
// needs outbound DNS for its webhook group; this focused run does not, so the SCIM walk can
// be proven on a runner without network. It is not a replacement for the sweep: only the sweep
// proves the whole route inventory.
func TestAPISmoke_SCIMOnly_SQLite(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	runSCIMOnly(t, serverBin, cliBin, harness.DBBackend{Name: "sqlite", NoMFAReason: apiSmokeNoMFAReason, EnableSCIM: true})
}

// TestAPISmoke_SCIMOnly_Postgres is the same focused run against PostgreSQL, gated on
// KEYORIX_TEST_PG_DSN like TestAPISmoke_Postgres.
func TestAPISmoke_SCIMOnly_Postgres(t *testing.T) {
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the PostgreSQL leg")
	}
	serverBin, cliBin := harness.BuildBinaries(t)
	runSCIMOnly(t, serverBin, cliBin, postgresSmokeBackend(dsn))
}

func runSCIMOnly(t *testing.T, serverBin, cliBin string, backend harness.DBBackend) {
	t.Helper()
	srv := harness.StartServer(t, serverBin, backend)
	t.Cleanup(srv.Close)

	c := newClient(t, srv.BaseURL)
	c.login("smoketestadmin", harness.BootstrapAdminPassword)
	ctx := &smokeCtx{
		t: t, c: c, cli: cliBin, cliEnv: srv.CLIEnv(),
		adminUsername: "smoketestadmin", adminPassword: harness.BootstrapAdminPassword,
		scimToken: srv.SCIMToken,
	}
	groupSCIM(ctx)

	hit := map[string]bool{}
	for _, k := range c.hitKeys() {
		hit[k] = true
	}
	scimRoutes := 0
	for _, r := range loadRoutes(t) {
		if !strings.HasPrefix(r.Pattern, "/scim/v2") {
			continue
		}
		scimRoutes++
		if !hit[r.key()] {
			t.Errorf("groupSCIM never reached %s", r.key())
		}
		if _, skipped := skipList[r.key()]; skipped {
			t.Errorf("%s is still in coverage.go's skipList although groupSCIM drives it", r.key())
		}
	}
	if scimRoutes == 0 {
		t.Fatal("routes.json lists no /scim/v2 route -- this check would be vacuous")
	}
}
