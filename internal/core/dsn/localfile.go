package dsn

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// localFileOptions lists, per backend type, the admin_dsn options that make the
// database driver read a file from the Keyorix server's own disk, or let the
// remote database server make it read one.
//
// An admin_dsn is written by a project admin, not by the server operator, so
// these options hand a project admin the server's filesystem:
//
//   - mysql allowAllFiles=true: go-sql-driver/mysql then answers a LOCAL INFILE
//     request from the remote server with ANY local path. A rogue server on a
//     public address (it passes the host guard) asks for the config file on the
//     first statement and the driver sends it.
//
//   - mongodb tls*File / ssl*File: the driver reads the CA / client certificate /
//     key from the named path before it dials (existence and parse oracle, and
//     the server's own certificate chain goes to the target).
//
//   - postgres sslrootcert / sslcert / sslkey / passfile / servicefile / service:
//     pgx reads them in ParseConfig (same oracle class).
//
//   - mongodb authMechanism=MONGODB-OIDC / MONGODB-AWS / GSSAPI: the driver
//     authenticates with the server's OWN ambient credentials (the pod's
//     service-account token file, AZURE_FEDERATED_TOKEN_FILE /
//     AWS_WEB_IDENTITY_TOKEN_FILE, the Azure/GCP metadata endpoints, AWS
//     environment/instance credentials, a Kerberos cache) and presents them to
//     the target host, which in a hostile admin_dsn is the attacker's server.
//
// Keys are lower case; matching is case-insensitive. The list was taken from the
// drivers' own option parsers (mongo connstring, pgconn config.go, mysql dsn.go);
// TestLocalFileOptionsCoverTheDrivers keeps it in step with go.mod.
var localFileOptions = map[string][]string{
	"mysql": {"allowallfiles"},
	"mongodb": {
		"tlscafile", "sslcertificateauthorityfile",
		"tlscertificatekeyfile", "sslclientcertificatekeyfile",
		"tlscertificatefile", "tlsprivatekeyfile",
	},
	"postgres": {"sslrootcert", "sslcert", "sslkey", "passfile", "servicefile", "service"},
}

// ambientCredentialMechanisms lists, per backend type, option values that make
// the driver authenticate with the server's own credentials instead of the
// username and password in the DSN. Key and the forbidden values, lower case.
var ambientCredentialMechanisms = map[string]struct {
	key    string
	values []string
}{
	"mongodb": {key: "authmechanism", values: []string{"mongodb-oidc", "mongodb-aws", "gssapi"}},
}

// ForbiddenOptionError is returned when an admin_dsn names an option from
// localFileOptions. It names only the option the caller wrote, so it is safe to
// show to the API caller.
type ForbiddenOptionError struct {
	Backend string
	Option  string
}

func (e *ForbiddenOptionError) Error() string {
	return fmt.Sprintf("admin_dsn option %q is not allowed for %s backends: it makes the server use its own files or credentials", e.Option, e.Backend)
}

var (
	localFileOptionRE = map[string]*regexp.Regexp{}
	ambientRE         = map[string]*regexp.Regexp{}
)

func init() {
	for backend, keys := range localFileOptions {
		// The key must follow a separator (start, ? & ; space, quote) and be
		// optionally closed by a quote and followed by '=', which covers URL query strings, mysql parameters,
		// mongodb options and libpq key/value pairs. Deliberately loose: a false
		// positive is a rejected DSN, a false negative is a file read.
		if rule, ok := ambientCredentialMechanisms[backend]; ok {
			ambientRE[backend] = regexp.MustCompile(`(?:^|[?&;,\s'"/])` + rule.key + `\s*=\s*(` + strings.Join(rule.values, "|") + `)`)
		}
		localFileOptionRE[backend] = regexp.MustCompile(`(?:^|[?&;,\s'"/])(` + strings.Join(keys, "|") + `)['"]?\s*=`)
	}
}

// CheckLocalFileOptions returns a *ForbiddenOptionError when adminDSN names an
// option that makes the driver for backendType touch the local filesystem. Other
// backend types are not checked. The DSN is examined as written and again with
// percent-escapes decoded (URL query keys are decoded by the drivers).
func CheckLocalFileOptions(backendType, adminDSN string) error {
	re, ok := localFileOptionRE[backendType]
	if !ok {
		return nil
	}
	forms := []string{strings.ToLower(adminDSN)}
	if dec, err := url.QueryUnescape(adminDSN); err == nil {
		forms = append(forms, strings.ToLower(dec))
	}
	if dec, err := url.PathUnescape(adminDSN); err == nil {
		forms = append(forms, strings.ToLower(dec))
	}
	for _, f := range forms {
		if m := re.FindStringSubmatch(f); m != nil {
			return &ForbiddenOptionError{Backend: backendType, Option: m[1]}
		}
		if are, ok := ambientRE[backendType]; ok {
			if m := are.FindStringSubmatch(f); m != nil {
				return &ForbiddenOptionError{Backend: backendType, Option: ambientCredentialMechanisms[backendType].key + "=" + m[1]}
			}
		}
	}
	return nil
}
