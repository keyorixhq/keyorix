package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// FuzzDSNTLSSettings_NeverMissesPgxVerification is the open-ended form of
// TestDSNTLSSettings_AgreesWithPgx, in the one direction that fails open: for
// any connection string pgx accepts and builds a certificate-verifying TLS
// config from, dsnTLSSettings must either refuse the string or read a mode
// that verifies too. Otherwise ValidateDatabaseTLS sees no verification, needs
// no CA, and pgx then verifies against its implicit trust store -- the
// fallback PG-VERIFYFULL-1 closes. (The `?`-in-userinfo and `?`-in-IPv6-host
// URL shapes were such misses.) The other direction -- reading verification
// pgx does not do -- only refuses a config, so it is not checked here.
//
// HOME, PGSSLMODE and PGSSLROOTCERT are cleared so no implicit CA exists;
// a DSN naming an sslrootcert pgx cannot load is skipped by pgx's own error.
func FuzzDSNTLSSettings_NeverMissesPgxVerification(f *testing.F) {
	f.Setenv("HOME", f.TempDir())
	f.Setenv("PGSSLMODE", "")
	f.Setenv("PGSSLROOTCERT", "")
	// A service file that turns verification on with no CA: any string that
	// selects it (service=svc, in any spelling pgx accepts) must be refused by
	// dsnSelectsService, or the oracle below sees pgx verify and the check not.
	svcFile := filepath.Join(f.TempDir(), "pg_service.conf")
	if err := os.WriteFile(svcFile, []byte("[svc]\nhost=db\nsslmode=verify-full\n"), 0o600); err != nil {
		f.Fatal(err)
	}
	f.Setenv("PGSERVICEFILE", svcFile)
	f.Setenv("PGSERVICE", "")
	for _, s := range []string{
		"service=svc",
		"host=db service='svc'",
		"postgres://u@db/k?service=svc",
		"postgres://u@db/k?servic%65=svc",
		"host=db sslmode=verify-full",
		"host=db sslmode=require sslmode=verify-ca",
		"host=db password='x sslmode=disable' sslmode=verify-full",
		`host=db sslmode=verify\-full`,
		"postgres://u@db/k?sslmode=verify-full",
		"postgres://u:pa?ss@db/k?sslmode=verify-full",
		"postgres://u@[::1?x]/k?sslmode=verify-full",
		"postgres://u@h1,h2:5433/k?sslmode=verify-ca",
		"postgresql://u@db/k?ssl%6Dode=verify-full",
		"postgres://u@db/k?sslmode=disable&sslrootcert=system",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, dsn string) {
		pc, perr := pgconn.ParseConfig(dsn)
		if perr != nil {
			return
		}
		tlsCfg := pc.TLSConfig
		if tlsCfg == nil || (tlsCfg.InsecureSkipVerify && tlsCfg.VerifyPeerCertificate == nil) {
			return // pgx does not verify the server: nothing to miss.
		}
		if sel, serr := dsnSelectsService(dsn); serr != nil || sel {
			return // a connection service is refused: fails closed.
		}
		mode, root, err := dsnTLSSettings(dsn)
		if err != nil {
			return // refused: fails closed.
		}
		if !(sslModeVerifies(mode) || root == SSLRootCertSystem || (root != "" && mode == "require")) {
			t.Fatalf("pgx verifies the server certificate for %q, but the check read sslmode=%q sslrootcert=%q (no verification, so no CA required)", dsn, mode, root)
		}
	})
}
