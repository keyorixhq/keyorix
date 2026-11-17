package dynamic

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// Revoke-only admin_dsn rewrites (#3980).
//
// #3952 refuses admin_dsn options that make a driver read a file on the Keyorix
// server (dsn.CheckLocalFileOptions). A config stored before #3952 can still carry
// one, and its leases are live on the target: MySQL and MongoDB users have no
// native expiry. Issue and Renew keep refusing such a DSN. Revoke instead removes
// the options it can drop without trusting the target more or reaching anything
// else, and connects with what is left:
//
//	backend   option                                         revoke does
//	postgres  sslcert, sslkey, sslpassword                   strip (no client certificate)
//	postgres  passfile                                       strip (the DSN's own password is required anyway)
//	postgres  sslrootcert                                    replace by sslrootcert=system: system trust store,
//	                                                         verify-full, no plaintext fallback
//	postgres  service, servicefile                           refuse (they name the target itself)
//	mysql     allowAllFiles                                  strip (LOCAL INFILE stays refused)
//	mongodb   tlsCAFile, sslCertificateAuthorityFile         strip, tls=true: system trust store
//	mongodb   tlsCertificateKeyFile, sslClientCertificate-   strip, tls=true (no client certificate)
//	          KeyFile, tlsCertificateFile, tlsPrivateKeyFile
//	mongodb   authMechanism=MONGODB-AWS/MONGODB-OIDC/GSSAPI  refuse (they change who authenticates)
//
// The rewrite does not need to parse the DSN exactly as the driver does: its
// output goes through the full issue-time checks again (CheckLocalFileOptions,
// and for postgres the key allow-list and the own-password check), so a DSN the
// rewrite misreads is refused or fails to connect, and a file option it misses
// is still refused. Any option CheckLocalFileOptions learns later is refused on
// revoke too until it is added above.

// postgresRevokeStrip lists the postgres keys a revoke removes. sslrootcert is
// also replaced, see parsePostgresRevokeDSN.
var postgresRevokeStrip = []string{"sslcert", "sslkey", "sslpassword", "passfile", "sslrootcert"}

// postgresRevokeRefuse lists the postgres keys a revoke cannot remove.
var postgresRevokeRefuse = []string{"service", "servicefile"}

const pgSpace = " \t\n\r\v\f"

// parsePostgresRevokeDSN is parsePostgresAdminDSN for Revoke: it returns the
// config with the strippable options removed, and the options it removed.
func parsePostgresRevokeDSN(adminDSN string) (*pgx.ConnConfig, []string, error) {
	stripped, removed, err := stripPostgresRevokeOptions(adminDSN)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := parsePostgresAdminDSN(stripped)
	if err != nil || !slices.Contains(removed, "sslrootcert") {
		return cfg, removed, err
	}

	// A root certificate made pgx verify the server (sslmode=require behaves as
	// verify-ca with one). Without the file, "system" is the only setting that
	// still verifies: pgx then uses the system pool and forces verify-full, which
	// is never weaker than what the stored DSN asked for and has no plaintext
	// fallback. The stripped DSN passed every issue-time check above and has no
	// sslrootcert left, so the only one in final is this literal.
	final := withPostgresSystemRoot(stripped)
	keys := append(slices.Clone(postgresAdminDSNKeys), "sslrootcert")
	sys, err := pgx.ParseConfigWithOptions(final, pgx.ParseConfigOptions{ParseConfigOptions: pgconn.ParseConfigOptions{ConnStringAllowedKeys: keys}})
	if err != nil {
		return nil, nil, errPostgresRevokeRewrite
	}
	// The appended setting must have changed the TLS settings and nothing else.
	if sys.Host != cfg.Host || sys.Port != cfg.Port || sys.User != cfg.User || sys.Password != cfg.Password || sys.Database != cfg.Database {
		return nil, nil, errPostgresRevokeRewrite
	}
	for _, c := range append([]*pgconn.FallbackConfig{{Host: sys.Host, Port: sys.Port, TLSConfig: sys.TLSConfig}}, sys.Fallbacks...) {
		if c.TLSConfig == nil || c.TLSConfig.InsecureSkipVerify || c.TLSConfig.RootCAs == nil {
			return nil, nil, errPostgresRevokeRewrite
		}
		dropClientCerts(c.TLSConfig)
	}
	return sys, removed, nil
}

var errPostgresRevokeRewrite = &dsn.ForbiddenOptionError{
	Backend: "postgres",
	Option:  "sslrootcert",
	Reason:  "revoke could not replace it by the system trust store; drop the lease's role by hand",
}

// stripPostgresRevokeOptions removes postgresRevokeStrip keys from adminDSN in
// either connection-string form, and refuses postgresRevokeRefuse keys.
func stripPostgresRevokeOptions(adminDSN string) (string, []string, error) {
	var removed []string
	// keep reports whether the setting named key stays, recording a removal.
	keep := func(key string) (bool, error) {
		k := strings.ToLower(key)
		if slices.Contains(postgresRevokeRefuse, k) {
			return false, &dsn.ForbiddenOptionError{Backend: "postgres", Option: k, Reason: "it takes the target from a server file, so revoke cannot remove it either; drop the lease's role by hand"}
		}
		if !slices.Contains(postgresRevokeStrip, k) {
			return true, nil
		}
		if !slices.Contains(removed, k) {
			removed = append(removed, k)
		}
		return false, nil
	}

	if strings.HasPrefix(adminDSN, "postgres://") || strings.HasPrefix(adminDSN, "postgresql://") {
		base := pgURLQueryStart(adminDSN)
		q := strings.IndexByte(adminDSN[base:], '?')
		if q < 0 {
			return adminDSN, nil, nil
		}
		q += base
		var kept []string
		// '&'-separated, the key percent-decoded, as pgconn's parseURLQueryParams.
		for pair := range strings.SplitSeq(adminDSN[q+1:], "&") {
			rawKey, _, _ := strings.Cut(pair, "=")
			key := strings.TrimSpace(rawKey)
			if dec, err := url.PathUnescape(key); err == nil {
				key = strings.TrimSpace(dec)
			}
			ok, err := keep(key)
			if err != nil {
				return "", nil, err
			}
			if ok {
				kept = append(kept, pair)
			}
		}
		if len(kept) == 0 {
			return adminDSN[:q], removed, nil
		}
		return adminDSN[:q+1] + strings.Join(kept, "&"), removed, nil
	}

	spans, err := pgKeywordValueSpans(adminDSN)
	if err != nil {
		return "", nil, fmt.Errorf("invalid postgres admin DSN: %w", err)
	}
	var b strings.Builder
	last := 0
	for _, s := range spans {
		ok, err := keep(s.key)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			b.WriteString(adminDSN[last:s.start])
			last = s.end
		}
	}
	b.WriteString(adminDSN[last:])
	return b.String(), removed, nil
}

// withPostgresSystemRoot appends sslrootcert=system to a DSN in either form.
func withPostgresSystemRoot(adminDSN string) string {
	if !strings.HasPrefix(adminDSN, "postgres://") && !strings.HasPrefix(adminDSN, "postgresql://") {
		return adminDSN + " sslrootcert=system"
	}
	if !strings.Contains(adminDSN[pgURLQueryStart(adminDSN):], "?") {
		return adminDSN + "?sslrootcert=system"
	}
	return adminDSN + "&sslrootcert=system"
}

// pgSpan is one key=value setting of a keyword/value postgres DSN:
// adminDSN[start:end] is the text to cut to remove it.
type pgSpan struct {
	key        string
	start, end int
}

// pgKeywordValueSpans splits a keyword/value DSN the way pgconn's
// parseKeywordValueSettings does (v5.11): whitespace includes \v, values are
// bare or single-quoted, backslash escapes the next byte. A span covers the
// setting and the whitespace after it.
func pgKeywordValueSpans(s string) ([]pgSpan, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, fmt.Errorf("NUL byte in connection string")
	}
	skip := func(i int) int {
		for i < len(s) && strings.IndexByte(pgSpace, s[i]) >= 0 {
			i++
		}
		return i
	}
	var out []pgSpan
	for i := skip(0); i < len(s); {
		start := i
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			return nil, fmt.Errorf("invalid keyword/value")
		}
		key := strings.Trim(s[i:i+eq], pgSpace)
		if key == "" || strings.ContainsAny(key, pgSpace) {
			return nil, fmt.Errorf("invalid keyword/value")
		}
		i = skip(i + eq + 1)
		if i < len(s) && s[i] == '\'' {
			for i++; i < len(s) && s[i] != '\''; i++ {
				if s[i] == '\\' {
					i++
				}
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated quoted string")
			}
			i++
		} else {
			for i < len(s) && strings.IndexByte(pgSpace, s[i]) < 0 {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			i = min(i, len(s))
		}
		i = skip(i)
		out = append(out, pgSpan{key: key, start: start, end: i})
	}
	return out, nil
}

// pgURLQueryStart returns the offset in a postgres URI after the userinfo, from
// where pgconn's parseURLSettings looks for host, path and query: the first '?'
// after it starts the query.
func pgURLQueryStart(s string) int {
	p := strings.TrimPrefix(strings.TrimPrefix(s, "postgresql://"), "postgres://")
	base := len(s) - len(p)
	if i := strings.IndexAny(p, "@/"); i >= 0 && p[i] == '@' {
		base += i + 1
	}
	return base
}

// parseMySQLRevokeDSN parses a mysql admin DSN for Revoke with allowAllFiles
// removed. go-sql-driver/mysql's ParseDSN reads no file; the one option
// localFileOptions lists for mysql is the driver's permission to answer LOCAL
// INFILE with any path, and without it the driver refuses every such request.
func parseMySQLRevokeDSN(adminDSN string) (*mysql.Config, []string, error) {
	cfg, err := mysql.ParseDSN(adminDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid mysql admin DSN: %w", err)
	}
	var removed []string
	if cfg.AllowAllFiles {
		removed = append(removed, "allowAllFiles")
		cfg.AllowAllFiles = false
	}
	// A misspelt case lands in Params (sent to the server as a session variable);
	// it reads no file either, drop it so the re-check below accepts the DSN.
	for k := range cfg.Params {
		if strings.EqualFold(k, "allowallfiles") {
			delete(cfg.Params, k)
			removed = append(removed, k)
		}
	}
	if err := dsn.CheckLocalFileOptions("mysql", cfg.FormatDSN()); err != nil {
		return nil, nil, err
	}
	return cfg, removed, nil
}

// mongoRevokeStrip lists the mongodb options (lower case) a revoke removes;
// every one of them turns TLS on in the driver, so the revoke keeps TLS on.
var mongoRevokeStrip = []string{
	"tlscafile", "sslcertificateauthorityfile",
	"tlscertificatekeyfile", "sslclientcertificatekeyfile",
	"tlscertificatefile", "tlsprivatekeyfile",
}

// mongoRevokeCompanions only mean something with a stripped key file.
var mongoRevokeCompanions = []string{"tlscertificatekeyfilepassword", "sslclientcertificatekeypassword"}

// stripMongoRevokeOptions removes mongoRevokeStrip options from a mongodb URI and,
// when it removed any, replaces every tls/ssl option by tls=true. Options are
// split on '&' and ';' as the driver splits them.
func stripMongoRevokeOptions(adminURI string) (string, []string) {
	scheme := strings.Index(adminURI, "://")
	if scheme < 0 {
		return adminURI, nil
	}
	slash := strings.IndexByte(adminURI[scheme+3:], '/')
	if slash < 0 {
		return adminURI, nil
	}
	q := strings.IndexByte(adminURI[scheme+3+slash:], '?')
	if q < 0 {
		return adminURI, nil
	}
	q += scheme + 3 + slash
	pairs := strings.FieldsFunc(adminURI[q+1:], func(r rune) bool { return r == ';' || r == '&' })
	var kept, removed []string
	lower := make([]string, len(pairs))
	for i, p := range pairs {
		rawKey, _, _ := strings.Cut(p, "=")
		key := rawKey
		if dec, err := url.QueryUnescape(rawKey); err == nil {
			key = dec
		}
		lower[i] = strings.ToLower(key)
		if slices.Contains(mongoRevokeStrip, lower[i]) {
			removed = append(removed, key)
		}
	}
	if len(removed) == 0 {
		return adminURI, nil
	}
	for i, p := range pairs {
		switch {
		case slices.Contains(mongoRevokeStrip, lower[i]), slices.Contains(mongoRevokeCompanions, lower[i]):
		case lower[i] == "tls", lower[i] == "ssl":
		default:
			kept = append(kept, p)
		}
	}
	kept = append(kept, "tls=true")
	return adminURI[:q+1] + strings.Join(kept, "&"), removed
}

// revokeStrippedError names the options a failed revoke connected without, so
// an operator reading revoke_failed knows why a CA or client certificate the
// stored DSN named was not used.
func revokeStrippedError(removed []string, systemRoots bool, err error) error {
	if len(removed) == 0 || err == nil {
		return err
	}
	how := "Keyorix does not read files named in an admin_dsn"
	if systemRoots {
		how += "; TLS was verified against the system trust store instead of the named CA file"
	}
	return fmt.Errorf("revoke ran without admin_dsn option(s) %s (%s): %w", strings.Join(removed, ", "), how, err)
}
