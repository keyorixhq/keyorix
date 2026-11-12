package dynamic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// PostgresEngine mints short-lived LOGIN roles on a target PostgreSQL database
// using the admin DSN, and drops them on revoke.
type PostgresEngine struct {
	// allowPrivateNetwork mirrors dynamic_secrets.allow_private_network_targets
	// (see New). When false, every connection re-validates the resolved
	// target address and refuses a private/link-local one (G48).
	allowPrivateNetwork bool
}

// dialPostgres connects to adminDSN, pinning the dial to a re-validated
// target address unless allowPrivateNetwork opts out. Replaces a bare
// pgx.Connect(ctx, adminDSN): that convenience wrapper offers no hook to
// control the underlying TCP dial, and — critically — the actual connection
// it makes would otherwise re-resolve adminDSN's host independently of
// whatever check ran when the config was created or the DSN last decrypted,
// letting a DNS-rebinding attacker swap in a private/link-local address
// between the two resolutions. pgx.ParseConfig + a custom
// pgconn.Config.DialFunc give the same TLS behavior as pgx.Connect (TLS, when
// configured, verifies against the original hostname — DialFunc only
// controls the raw TCP dial beneath it) while pinning the raw connection to
// the specific address just validated.
//
// pgx resolves the hostname itself via cfg.LookupFunc BEFORE ever calling
// DialFunc (DialFunc is invoked once per candidate address LookupFunc
// returns, as a literal IP, not the hostname) — so DialFunc's own Resolve
// alone is not enough to close the DNS-rebinding gap; without also pointing
// LookupFunc at the SAME resolver, pgx would still perform its own
// independent (real-DNS) hostname resolution ahead of DialFunc. Wiring both
// through dialResolve makes the whole resolve-then-dial sequence consistent,
// and DialFunc's own re-validation of whatever literal IP it receives is
// defense-in-depth regardless of which step did the resolving.
func dialPostgres(ctx context.Context, adminDSN string, allowPrivateNetwork bool) (*pgx.Conn, error) {
	cfg, err := parsePostgresAdminDSN(adminDSN)
	if err != nil {
		return nil, err
	}
	return connectPostgres(ctx, cfg, allowPrivateNetwork)
}

// dialPostgresForRevoke is dialPostgres for Revoke only: the options that make
// pgx read a server file are removed first (parsePostgresRevokeDSN, #3980), so a
// config stored before #3952 can still drop the roles it issued.
func dialPostgresForRevoke(ctx context.Context, adminDSN string, allowPrivateNetwork bool) (*pgx.Conn, error) {
	cfg, removed, err := parsePostgresRevokeDSN(adminDSN)
	if err != nil {
		return nil, err
	}
	conn, err := connectPostgres(ctx, cfg, allowPrivateNetwork)
	return conn, revokeStrippedError(removed, slices.Contains(removed, "sslrootcert"), err)
}

func connectPostgres(ctx context.Context, cfg *pgx.ConnConfig, allowPrivateNetwork bool) (*pgx.Conn, error) {
	if !allowPrivateNetwork {
		cfg.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
			addrs, err := dialResolve(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]string, len(addrs))
			for i, a := range addrs {
				ips[i] = a.IP.String()
			}
			return ips, nil
		}
		cfg.DialFunc = (&netutil.Dialer{Disallow: netutil.IsPrivateOrLinkLocal, Resolve: dialResolve}).DialContext
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to target: %w", err)
	}
	return conn, nil
}

// postgresAdminDSNKeys is the allow-list of keys a postgres admin_dsn may set.
// pgx refuses any other key before it reads a file or resolves a host
// (ParseConfigOptions.ConnStringAllowedKeys), so a key pgx learns in a later
// version is refused too. None of these makes pgx read the server's disk.
var postgresAdminDSNKeys = []string{
	"host", "port", "dbname", "user", "password",
	"sslmode", "sslsni", "connect_timeout", "application_name",
	"target_session_attrs", "channel_binding", "require_auth",
}

var pgDisallowedKeyRE = regexp.MustCompile(`connection string key "([a-z_]{1,64})" is not in ConnStringAllowedKeys`)

// parsePostgresAdminDSN parses an admin_dsn the way dialPostgres needs it.
// admin_dsn is project-admin input, and pgx would otherwise:
//   - read sslrootcert/sslcert/sslkey/passfile/servicefile/service from the
//     server's disk (refused by the textual check, then by the allow-list, which
//     also covers separators the textual check might not know);
//   - fill a password the DSN leaves out (or sets empty) from the server's
//     PGPASSWORD, service file or ~/.pgpass, and send it to the DSN's host;
//   - present the server's default client certificate (~/.postgresql/
//     postgresql.crt or PGSSLCERT/PGSSLKEY) to any host that asks for one.
//
// The password must therefore be written in the DSN itself, and client
// certificates are dropped (sslcert/sslkey cannot be set by the DSN, so any
// certificate is the server's own). Settings that only make the connection
// stricter (PGSSLMODE, a default root.crt) still apply.
func parsePostgresAdminDSN(adminDSN string) (*pgx.ConnConfig, error) {
	if err := dsn.CheckLocalFileOptions("postgres", adminDSN); err != nil {
		return nil, err
	}
	opts := pgx.ParseConfigOptions{ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: postgresAdminDSNKeys}}
	cfg, err := pgx.ParseConfigWithOptions(adminDSN, opts)
	if err != nil {
		if m := pgDisallowedKeyRE.FindStringSubmatch(err.Error()); m != nil {
			return nil, &dsn.ForbiddenOptionError{Backend: "postgres", Option: m[1], Reason: "allowed options are " + strings.Join(postgresAdminDSNKeys, ", ")}
		}
		if strings.Contains(err.Error(), "ConnStringAllowedKeys") {
			return nil, &dsn.ForbiddenOptionError{Backend: "postgres", Option: "?", Reason: "allowed options are " + strings.Join(postgresAdminDSNKeys, ", ")}
		}
		return nil, fmt.Errorf("connect to target: %w", err)
	}

	// Did the DSN itself set a password? The same parse with "password" left out
	// of the allow-list succeeds only when it did not; nothing else differs.
	noPassword := slices.DeleteFunc(slices.Clone(postgresAdminDSNKeys), func(k string) bool { return k == "password" })
	_, probeErr := pgconn.ParseConfigWithOptions(adminDSN, pgconn.ParseConfigOptions{ConnStringAllowedKeys: noPassword})
	if probeErr == nil {
		return nil, errAmbientPostgresPassword
	}
	// With the key present pgx only replaces an empty value, from ~/.pgpass. Parse
	// the same DSN again with passfile pointing at the null device: a connection
	// string key overrides the default and PGPASSFILE, so what comes out is the
	// password the DSN itself carries. It must be non-empty and be the one pgx
	// will send.
	own, err := postgresDSNOwnPassword(adminDSN)
	if err != nil || own == "" || own != cfg.Password {
		return nil, errAmbientPostgresPassword
	}

	dropClientCerts(cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		dropClientCerts(fb.TLSConfig)
	}
	return cfg, nil
}

var errAmbientPostgresPassword = &dsn.ForbiddenOptionError{
	Backend: "postgres",
	Option:  "password",
	Reason:  "admin_dsn must contain the admin password; the server's own PGPASSWORD, ~/.pgpass and service files are never used",
}

// postgresDSNOwnPassword returns the password adminDSN itself carries, parsed
// with passfile=<os.DevNull> so ~/.pgpass (and PGPASSFILE) cannot fill it in.
// An error means the DSN could not be rewritten safely; the caller refuses it.
func postgresDSNOwnPassword(adminDSN string) (string, error) {
	probe := adminDSN
	if strings.HasPrefix(adminDSN, "postgres://") || strings.HasPrefix(adminDSN, "postgresql://") {
		u, err := url.Parse(adminDSN)
		if err != nil {
			return "", err
		}
		u.Fragment, u.RawFragment = "", ""
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += "passfile=" + url.QueryEscape(os.DevNull)
		probe = u.String()
	} else {
		probe += " passfile=" + os.DevNull
	}
	keys := append(slices.Clone(postgresAdminDSNKeys), "passfile")
	c, err := pgconn.ParseConfigWithOptions(probe, pgconn.ParseConfigOptions{ConnStringAllowedKeys: keys})
	if err != nil {
		return "", err
	}
	return c.Password, nil
}

func dropClientCerts(c *tls.Config) {
	if c == nil {
		return
	}
	c.Certificates = nil
	c.GetClientCertificate = nil
}

func (e *PostgresEngine) BackendType() string      { return "postgres" }
func (e *PostgresEngine) IsEphemeralBackend() bool { return false }

// RevokeInvalidatesCredential is always true: DROP ROLE really removes the
// account, so a subsequent connection attempt with it fails immediately.
func (e *PostgresEngine) RevokeInvalidatesCredential(_ string) bool { return true }

// SupportsNativeExpiry is true: PostgreSQL roles carry a VALID UNTIL, so the
// credential disables itself at expiry even without the auto-revoke sweeper.
func (e *PostgresEngine) SupportsNativeExpiry() bool { return true }

// Issue creates a `kx_dyn_<random>` LOGIN role with a random password and a
// VALID UNTIL of now+ttl, then runs the operator's creation template ({{name}} →
// the role). Role name and password are crypto/rand from an identifier/quote-safe
// alphabet, so neither can break out of the SQL; the role name is additionally
// quoted via pgx.Identifier. The template is operator-authored (trusted) and is
// the documented SQL-injection trust boundary.
func (e *PostgresEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (Credential, string, error) {
	conn, err := dialPostgres(ctx, adminDSN, e.allowPrivateNetwork)
	if err != nil {
		return Credential{}, "", err
	}
	defer func() { _ = conn.Close(ctx) }()

	suffix, err := randString(16)
	if err != nil {
		return Credential{}, "", err
	}
	role := "kx_dyn_" + suffix
	password, err := randString(32)
	if err != nil {
		return Credential{}, "", err
	}
	ident := pgx.Identifier{role}.Sanitize()
	validUntil := time.Now().Add(ttl).UTC().Format(time.RFC3339)

	if _, err := conn.Exec(ctx, fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s' VALID UNTIL '%s'", ident, password, validUntil)); err != nil {
		return Credential{}, "", fmt.Errorf("create role: %w", err)
	}

	if tmpl := strings.TrimSpace(creationTemplate); tmpl != "" {
		grant := strings.ReplaceAll(tmpl, "{{name}}", ident)
		if _, err := conn.Exec(ctx, grant); err != nil {
			// Don't leak a half-provisioned role if the template fails.
			_, _ = conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ident))
			return Credential{}, "", fmt.Errorf("run creation template: %w", err)
		}
	}
	return Credential{Username: role, Password: password}, role, nil
}

// Revoke terminates the role's sessions, reassigns/drops its owned objects, then
// drops the role. Each step is best-effort except the final DROP ROLE, whose
// failure is reported so the lease is marked revoke_failed rather than silently
// left active.
//
// It connects through dialPostgresForRevoke: an admin_dsn option Issue refuses
// for reading a server file is removed instead of refused (#3980).
func (e *PostgresEngine) Revoke(ctx context.Context, adminDSN, roleName string) error {
	conn, err := dialPostgresForRevoke(ctx, adminDSN, e.allowPrivateNetwork)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	ident := pgx.Identifier{roleName}.Sanitize()
	_, _ = conn.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", roleName)
	_, _ = conn.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", ident))
	_, _ = conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", ident))
	if _, err := conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", ident)); err != nil {
		return fmt.Errorf("drop role %s: %w", roleName, err)
	}
	return nil
}

// Renew extends the role's VALID UNTIL to expiresAt, so the credential stays
// usable for the renewed window without re-issuing.
func (e *PostgresEngine) Renew(ctx context.Context, adminDSN, roleName string, expiresAt time.Time) error {
	conn, err := dialPostgres(ctx, adminDSN, e.allowPrivateNetwork)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	ident := pgx.Identifier{roleName}.Sanitize()
	validUntil := expiresAt.UTC().Format(time.RFC3339)
	if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s VALID UNTIL '%s'", ident, validUntil)); err != nil {
		return fmt.Errorf("renew role %s: %w", roleName, err)
	}
	return nil
}
