package dynamic

import (
	"net/url"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// Revoke must keep working on a config stored before the local-file options
// were refused: the credential it drops is live on the target, and MongoDB and
// MySQL have no native expiry to end it. Issue and Renew keep refusing those
// configs. The functions below only rewrite the DSN a Revoke connects with; the
// result still goes through the normal connect path, so dsn.CheckLocalFileOptions
// and the driver allow-lists remain the single gate. If a rewrite misses a
// spelling, the connection is refused exactly as it was before.
//
// An option is removed only when that cannot change which host is contacted,
// which credential is sent, or how far the connection is trusted. Anything else
// stays refused, and the lease stays revoke_failed:
//   - postgres service/servicefile: the file can name the host, so dropping the
//     key would send the admin password to a different server;
//   - postgres with no password in the DSN: the password was in a file;
//   - mongodb ambient authMechanism values: there is no credential left to send.
//
// Without its CA file a connection verifies against the host's system roots. A
// target signed by a private CA then fails verification (no silent downgrade);
// the operator adds that CA to the system trust store of the Keyorix host.

// postgresRevokeStrippedKeys are the postgres keys a Revoke may drop.
var postgresRevokeStrippedKeys = map[string]bool{
	"sslrootcert": true, "sslcert": true, "sslkey": true, "sslpassword": true, "passfile": true,
}

// mongoRevokeStrippedKeys are the mongodb URI options a Revoke may drop: the
// file options, and the passwords that only decrypt those files.
var mongoRevokeStrippedKeys = map[string]bool{
	"tlscafile": true, "sslcertificateauthorityfile": true,
	"tlscertificatekeyfile": true, "sslclientcertificatekeyfile": true,
	"tlscertificatefile": true, "tlsprivatekeyfile": true,
	"tlscertificatekeyfilepassword": true, "sslclientcertificatekeypassword": true,
}

// postgresDSNPair is one key/value of a postgres DSN and the text it came from.
type postgresDSNPair struct{ key, value, raw string }

const postgresDSNSpace = " \t\n\r\v\f"

// postgresRevokeDSN returns adminDSN without postgresRevokeStrippedKeys. It
// returns adminDSN unchanged when there is nothing to remove or it cannot be
// tokenized, leaving the refusal to the connect path.
func postgresRevokeDSN(adminDSN string) string {
	if strings.HasPrefix(adminDSN, "postgres://") || strings.HasPrefix(adminDSN, "postgresql://") {
		return postgresRevokeURL(adminDSN)
	}
	pairs, ok := postgresKeywordValuePairs(adminDSN)
	if !ok {
		return adminDSN
	}
	kept, changed := postgresRevokeKeep(pairs)
	if !changed {
		return adminDSN
	}
	return strings.Join(kept, " ")
}

// postgresRevokeURL rewrites only the query of a postgres URI. As in pgx, the
// userinfo runs to an '@' found before any '/', so it may contain a '?'.
func postgresRevokeURL(adminDSN string) string {
	from := strings.Index(adminDSN, "://") + len("://")
	if i := strings.IndexAny(adminDSN[from:], "@/"); i >= 0 && adminDSN[from+i] == '@' {
		from += i + 1
	}
	i := strings.IndexByte(adminDSN[from:], '?')
	if i < 0 {
		return adminDSN
	}
	base, query := adminDSN[:from+i], adminDSN[from+i+1:]
	var pairs []postgresDSNPair
	for raw := range strings.SplitSeq(query, "&") {
		rawKey, rawValue, _ := strings.Cut(raw, "=")
		key, err := url.PathUnescape(rawKey)
		if err != nil {
			return adminDSN
		}
		value, err := url.PathUnescape(rawValue)
		if err != nil {
			return adminDSN
		}
		pairs = append(pairs, postgresDSNPair{key: key, value: value, raw: raw})
	}
	kept, changed := postgresRevokeKeep(pairs)
	if !changed {
		return adminDSN
	}
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

// postgresRevokeKeep drops the stripped keys and, when removing sslrootcert
// would lower the verification pgx applied, states the mode that keeps it.
func postgresRevokeKeep(pairs []postgresDSNPair) (kept []string, changed bool) {
	var rootCert, sslMode string
	for _, p := range pairs {
		switch strings.ToLower(p.key) {
		case "sslrootcert":
			rootCert = p.value
		case "sslmode":
			sslMode = p.value
		}
	}
	mode := sslModeWithoutRootCert(sslMode, rootCert)
	for _, p := range pairs {
		key := strings.ToLower(p.key)
		if postgresRevokeStrippedKeys[key] {
			changed = true
			continue
		}
		if key == "sslmode" && mode != "" {
			continue
		}
		kept = append(kept, p.raw)
	}
	if changed && mode != "" {
		kept = append(kept, "sslmode="+mode)
	}
	return kept, changed
}

// sslModeWithoutRootCert returns the sslmode to state once sslrootcert is gone,
// or "" to leave the DSN's own. pgx treats sslmode=require with a root
// certificate as verify-ca, and sslrootcert=system as verify-full whatever the
// sslmode; without the key either would become a connection that verifies
// nothing, carrying the admin password. A root certificate alongside "prefer",
// "allow" or "disable" was never verified, so those are unchanged.
func sslModeWithoutRootCert(sslMode, rootCert string) string {
	if sslMode == "" {
		sslMode = os.Getenv("PGSSLMODE")
	}
	switch {
	case rootCert == "":
		return ""
	case rootCert == "system":
		return "verify-full"
	case sslMode == "require":
		return "verify-ca"
	}
	return ""
}

// postgresKeywordValuePairs splits a libpq keyword/value string the way pgconn's
// parseKeywordValueSettings does. false means pgx would reject it too.
func postgresKeywordValuePairs(s string) ([]postgresDSNPair, bool) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, false
	}
	var pairs []postgresDSNPair
	rest := strings.TrimLeft(s, postgresDSNSpace)
	for rest != "" {
		start := rest
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return nil, false
		}
		key := strings.Trim(rest[:eq], postgresDSNSpace)
		if key == "" || strings.ContainsAny(key, postgresDSNSpace) {
			return nil, false
		}
		rest = strings.TrimLeft(rest[eq+1:], postgresDSNSpace)
		var value string
		switch {
		case rest == "":
		case rest[0] != '\'':
			end := 0
			for ; end < len(rest); end++ {
				if strings.IndexByte(postgresDSNSpace, rest[end]) >= 0 {
					break
				}
				if rest[end] == '\\' {
					end++
					if end == len(rest) {
						break
					}
				}
			}
			value = unescapePostgresValue(rest[:end])
			rest = rest[end:]
		default:
			body := rest[1:]
			end := 0
			for ; end < len(body) && body[end] != '\''; end++ {
				if body[end] == '\\' {
					end++
				}
			}
			if end >= len(body) {
				return nil, false
			}
			value = unescapePostgresValue(body[:end])
			rest = body[end+1:]
		}
		pairs = append(pairs, postgresDSNPair{key: key, value: value, raw: start[:len(start)-len(rest)]})
		rest = strings.TrimLeft(rest, postgresDSNSpace)
	}
	return pairs, true
}

func unescapePostgresValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i == len(s) {
				break
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mongoRevokeURI returns adminURI without mongoRevokeStrippedKeys. The driver
// splits the query on '&' and ';' and decodes keys, so this does too.
func mongoRevokeURI(adminURI string) string {
	base, query, ok := strings.Cut(adminURI, "?")
	if !ok {
		return adminURI
	}
	var kept []string
	changed := false
	for _, raw := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		rawKey, _, _ := strings.Cut(raw, "=")
		key, err := url.QueryUnescape(rawKey)
		if err == nil && mongoRevokeStrippedKeys[strings.ToLower(key)] {
			changed = true
			continue
		}
		kept = append(kept, raw)
	}
	if !changed {
		return adminURI
	}
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

// mysqlRevokeDSN returns adminDSN with allowAllFiles removed, using the driver's
// own parser and formatter. The refused key matches whatever its value, so
// allowAllFiles=false is rewritten too.
func mysqlRevokeDSN(adminDSN string) string {
	if dsn.CheckLocalFileOptions("mysql", adminDSN) == nil {
		return adminDSN
	}
	cfg, err := mysql.ParseDSN(adminDSN)
	if err != nil {
		return adminDSN
	}
	cfg.AllowAllFiles = false
	return cfg.FormatDSN()
}
