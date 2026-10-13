package config

import (
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
	for _, s := range []string{
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
		mode, root, err := dsnTLSSettings(dsn)
		if err != nil {
			return // refused: fails closed.
		}
		if !(sslModeVerifies(mode) || root == SSLRootCertSystem || (root != "" && mode == "require")) {
			t.Fatalf("pgx verifies the server certificate for %q, but the check read sslmode=%q sslrootcert=%q (no verification, so no CA required)", dsn, mode, root)
		}
	})
}

// FuzzEffectiveSSLMode_NeverMissesPgxPlaintext is the open-ended form of the
// plaintext comparison in TestDSNTLSSettings_AgreesWithPgx (PG-TLS-2), in the
// direction that fails open: for any connection string pgx accepts and can
// run without TLS (no TLS config, or a plaintext fallback), the effective
// sslmode the insecure-settings registry reads must be disable, allow or
// prefer, or the string must be refused. Otherwise the registry reports no
// plaintext risk for a connection that has one. The other direction
// (reporting a risk pgx does not have, e.g. prefer with sslnegotiation=direct,
// which pgx upgrades to require) only over-reports, so it is not checked.
//
// A Unix-socket host (pgx's default when the string names no host) never
// uses TLS and never crosses the network, so pgxMayBePlaintext does not count
// it.
//
// HOME, PGSSLMODE, PGSSLROOTCERT and PGSERVICE are cleared so no environment
// or service file supplies a setting.
func FuzzEffectiveSSLMode_NeverMissesPgxPlaintext(f *testing.F) {
	f.Setenv("HOME", f.TempDir())
	f.Setenv("PGSSLMODE", "")
	f.Setenv("PGSSLROOTCERT", "")
	f.Setenv("PGSERVICE", "")
	for _, s := range []string{
		"host=db",
		"host=db sslmode=disable",
		"host=db sslmode=allow",
		"host=db sslmode=require sslmode=prefer",
		"host=db password='x sslmode=require' sslmode=prefer",
		"postgres://u@db/k",
		"postgres://u@db/k?sslmode=require&sslmode=prefer",
		"postgres://u@db/k?ssl=true&sslmode=disable",
		"postgres://u@db/k?sslmode=disable&ssl=true&ssl=false",
		"postgres://u:p?sslmode=require@db/k?sslmode=disable",
		"postgresql://u@db/k?ssl%6Dode=allow",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, dsn string) {
		if dsn == "" {
			return // an empty dsn means "build it from the fields", which always state sslmode
		}
		pc, perr := pgconn.ParseConfig(dsn)
		if perr != nil {
			return
		}
		if !pgxMayBePlaintext(pc) {
			return // pgx always encrypts: nothing to miss.
		}
		mode, err := EffectiveDatabaseSSLMode(&DatabaseConfig{DSN: dsn})
		if err != nil {
			return // refused: fails closed.
		}
		if !sslModeMayBePlaintext(mode) {
			t.Fatalf("pgx can connect to %q without TLS, but the effective sslmode read is %q", dsn, mode)
		}
	})
}
