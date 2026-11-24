package dynamic

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// sqlTransportPolicy is the operator's transport policy for the postgres and
// mysql engines (#4374): an admin_dsn whose connection does not verify the server
// certificate is refused unless allowInsecure (the operator flag) is set. The
// decision reads the parsed driver config (postgresTransportWeakness,
// mysqlTransportWeakness), the one the engine then connects with.
//
// Core refuses such a DSN when it is saved; this is the second check, at connect
// time. storedGrace mirrors dsn.StoredSQLTransportGrace: while it holds, every
// admin_dsn reaching the engine was stored (save refuses new ones), so it connects
// with a WARNING instead of being refused. A field, not the constant, so tests
// drive both sides of the cut-over.
type sqlTransportPolicy struct {
	allowInsecure bool
	storedGrace   bool
}

func newSQLTransportPolicy(allowInsecure bool) sqlTransportPolicy {
	return sqlTransportPolicy{allowInsecure: allowInsecure, storedGrace: dsn.StoredSQLTransportGrace}
}

// refuses reports whether a weak admin_dsn is refused (Issue, Renew) or, on
// Revoke, upgraded to a verified connection.
func (p sqlTransportPolicy) refuses() bool { return !p.allowInsecure && !p.storedGrace }

// check refuses w, or logs the WARNING when the policy lets it through. nil w
// (the connection verifies) passes silently.
func (p sqlTransportPolicy) check(w *dsn.TransportWeakness) error {
	if w == nil {
		return nil
	}
	if p.refuses() {
		return w.Refusal()
	}
	log.Print(w.Warning(p.allowInsecure))
	return nil
}

// postgresVerifies reports whether one pgx connection attempt checks the server
// certificate: TLS with the standard verification (verify-full), or pgx's own
// chain check in VerifyPeerCertificate (verify-ca, and require with a root
// certificate) against a root the operator installed (PGSSLROOTCERT or
// ~/.postgresql/root.crt; an admin_dsn cannot name one). verify-ca without such a
// root is not verification: pgx then checks the chain against the system pool and
// no host name, so any publicly trusted certificate for any name passes (libpq
// refuses verify-ca without a root certificate).
func postgresVerifies(c *tls.Config) bool {
	return c != nil && (!c.InsecureSkipVerify || (c.VerifyPeerCertificate != nil && c.RootCAs != nil))
}

// postgresTransportWeakness decides from a parsed pgx config, so every spelling
// of sslmode, its default (prefer) and a PGSSLMODE environment value are read the
// way pgx will connect. Every attempt (first host, its fallback, every other host)
// must verify. Only verify-ca and verify-full pass; disable, allow, prefer and
// require do not.
func postgresTransportWeakness(cfg *pgconn.Config) *dsn.TransportWeakness {
	first := []*tls.Config{cfg.TLSConfig}
	verified := postgresVerifies(cfg.TLSConfig)
	plaintext := cfg.TLSConfig == nil
	for _, fb := range cfg.Fallbacks {
		verified = verified && postgresVerifies(fb.TLSConfig)
		plaintext = plaintext || fb.TLSConfig == nil
		if fb.Host == cfg.Host && fb.Port == cfg.Port {
			first = append(first, fb.TLSConfig)
		}
	}
	if verified {
		return nil
	}
	if network, _ := pgconn.NetworkAddress(cfg.Host, cfg.Port); network == "unix" {
		return &dsn.TransportWeakness{Backend: "postgres", Option: "host (Unix socket, no TLS)", Plaintext: true}
	}
	// Name the mode by what pgx will try for the first host: one attempt or two,
	// plaintext first or TLS first.
	mode := "sslmode"
	switch {
	case first[0] == nil && len(first) > 1:
		mode = "sslmode=allow"
	case first[0] == nil:
		mode = "sslmode=disable"
	case first[0].VerifyPeerCertificate != nil:
		mode = "sslmode=verify-ca (no root certificate installed: any public certificate is accepted)"
	case !postgresVerifies(first[0]) && len(first) > 1 && first[1] == nil:
		mode = "sslmode=prefer"
	case !postgresVerifies(first[0]):
		mode = "sslmode=require"
	}
	return &dsn.TransportWeakness{Backend: "postgres", Option: mode, Plaintext: plaintext}
}

// mysqlTransportWeakness decides from a parsed go-sql-driver config. Only TLS with
// certificate verification and no plaintext fallback passes: tls=true, or a
// registered config that verifies. tls=false (also the default), skip-verify,
// preferred and allowFallbackToPlaintext=true do not.
func mysqlTransportWeakness(cfg *mysql.Config) *dsn.TransportWeakness {
	switch {
	case cfg.TLS == nil:
		return &dsn.TransportWeakness{Backend: "mysql", Option: "tls=false", Plaintext: true}
	case cfg.TLS.InsecureSkipVerify && cfg.AllowFallbackToPlaintext:
		return &dsn.TransportWeakness{Backend: "mysql", Option: "tls=preferred", Plaintext: true}
	case cfg.TLS.InsecureSkipVerify && cfg.TLSConfig == "skip-verify":
		return &dsn.TransportWeakness{Backend: "mysql", Option: "tls=skip-verify"}
	case cfg.TLS.InsecureSkipVerify:
		// A registered TLS config, by a name that comes from the DSN: not quoted.
		return &dsn.TransportWeakness{Backend: "mysql", Option: "tls (a registered config that skips verification)"}
	case cfg.AllowFallbackToPlaintext:
		return &dsn.TransportWeakness{Backend: "mysql", Option: "allowFallbackToPlaintext=true", Plaintext: true}
	}
	return nil
}

// AdminDSNTransportWeakness implements ports.DynamicAdminDSNTransportInspector:
// core asks it when an admin_dsn is saved and before each issue. It parses
// adminDSN exactly as Issue does; a DSN Issue would refuse or cannot parse
// answers nil (save then stores it as before, and Issue refuses it).
func (e *PostgresEngine) AdminDSNTransportWeakness(adminDSN string) *dsn.TransportWeakness {
	cfg, err := parsePostgresAdminDSN(adminDSN)
	if err != nil {
		return nil
	}
	return postgresTransportWeakness(&cfg.Config)
}

// AdminDSNTransportWeakness is PostgresEngine.AdminDSNTransportWeakness for mysql.
func (e *MySQLEngine) AdminDSNTransportWeakness(adminDSN string) *dsn.TransportWeakness {
	if dsn.CheckLocalFileOptions("mysql", adminDSN) != nil {
		return nil
	}
	cfg, err := mysql.ParseDSN(adminDSN)
	if err != nil {
		return nil
	}
	return mysqlTransportWeakness(cfg)
}

// verifiedTLS returns c (or a new config) with the standard certificate and
// hostname verification for host. Other settings of c are kept: ALPN for
// sslnegotiation=direct, a RootCAs pool the operator's environment put there.
func verifiedTLS(c *tls.Config, host string) *tls.Config {
	out := &tls.Config{MinVersion: tls.VersionTLS12}
	if c != nil {
		out = c.Clone()
		out.MinVersion = max(out.MinVersion, tls.VersionTLS12)
	}
	out.InsecureSkipVerify = false
	out.VerifyPeerCertificate = nil
	out.ServerName = host
	return out
}

// upgradePostgresToVerifyFull rewrites every network connection attempt of cfg to
// TLS with full verification, as sslmode=verify-full would: the plaintext attempt
// of allow/prefer is dropped (one attempt per host remains), and certificate and
// hostname are checked. Used by Revoke instead of refusing (#3980 reasoning: a
// refused revoke leaves the account live). A Unix-socket attempt has no TLS in
// pgx and stays as it is: it does not leave the host.
func upgradePostgresToVerifyFull(cfg *pgconn.Config) {
	// A plaintext attempt (disable, allow) takes the settings of the host's TLS
	// attempt when it has one: the operator's RootCAs and the ALPN of
	// sslnegotiation=direct live there.
	tlsOf := map[string]*tls.Config{}
	note := func(host string, port uint16, c *tls.Config) {
		if key := net.JoinHostPort(host, fmt.Sprint(port)); c != nil && tlsOf[key] == nil {
			tlsOf[key] = c
		}
	}
	note(cfg.Host, cfg.Port, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		note(fb.Host, fb.Port, fb.TLSConfig)
	}
	upgrade := func(host string, port uint16, c *tls.Config) *tls.Config {
		if network, _ := pgconn.NetworkAddress(host, port); network == "unix" {
			return c
		}
		if c == nil {
			c = tlsOf[net.JoinHostPort(host, fmt.Sprint(port))]
		}
		return verifiedTLS(c, host)
	}
	cfg.TLSConfig = upgrade(cfg.Host, cfg.Port, cfg.TLSConfig)
	seen := map[string]bool{net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)): true}
	kept := cfg.Fallbacks[:0]
	for _, fb := range cfg.Fallbacks {
		key := net.JoinHostPort(fb.Host, fmt.Sprint(fb.Port))
		if seen[key] {
			continue
		}
		seen[key] = true
		fb.TLSConfig = upgrade(fb.Host, fb.Port, fb.TLSConfig)
		kept = append(kept, fb)
	}
	cfg.Fallbacks = kept
}

// upgradeMySQLToVerified makes cfg use TLS with certificate and hostname
// verification and no plaintext fallback, as tls=true would. Used by Revoke. A
// Unix-socket connection stays as it is (it does not leave the host), as for
// postgres.
func upgradeMySQLToVerified(cfg *mysql.Config) {
	if cfg.Net == "unix" {
		return
	}
	host := cfg.Addr
	if h, _, err := net.SplitHostPort(cfg.Addr); err == nil {
		host = h
	}
	cfg.TLS = verifiedTLS(cfg.TLS, host)
	cfg.AllowFallbackToPlaintext = false
}

// revokeTransportUpgradedError names the option a failed revoke dropped, so an
// operator reading revoke_failed knows why a target with an untrusted certificate
// (or without TLS) now fails the connection.
func revokeTransportUpgradedError(w *dsn.TransportWeakness, err error) error {
	if w == nil || err == nil {
		return err
	}
	return fmt.Errorf("revoke ran without admin_dsn option %s (TLS with the server certificate verified): %w", w.Option, err)
}
