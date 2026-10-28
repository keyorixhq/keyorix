package config

import "fmt"

// DatabaseTLSFiles are the file locations of a PostgreSQL connection's TLS
// material, as the connection will use them (RD-CBOM-TAILS-1, crypto inventory).
// Locations only: nothing here opens a file.
type DatabaseTLSFiles struct {
	// RootCert is the CA bundle path; RootCertSystem is true for sslrootcert=system.
	RootCert       string
	RootCertSystem bool
	// ClientCert and ClientKey come from the dsn's sslcert / sslkey; ssl_mode has
	// no client-certificate field. PGSSLCERT and libpq's default
	// ~/.postgresql/postgresql.crt are not reported (they depend on the process
	// environment, not on configuration).
	ClientCert string
	ClientKey  string
	// SSLMode is the mode the connection really runs with (see resolveDatabaseTLS).
	SSLMode string
}

// DatabaseTLSFilesOf reports d's TLS file locations, or an error when
// ValidateDatabaseTLS would refuse d. It never echoes the dsn.
func DatabaseTLSFilesOf(d *DatabaseConfig) (DatabaseTLSFiles, error) {
	t, err := resolveDatabaseTLS(d)
	if err != nil {
		return DatabaseTLSFiles{}, err
	}
	f := DatabaseTLSFiles{SSLMode: t.mode, RootCertSystem: t.rootCert == SSLRootCertSystem}
	if !f.RootCertSystem {
		f.RootCert = t.rootCert
	}
	if d.DSN != "" {
		s, err := parseDSNTLS(d.DSN)
		if err != nil {
			return DatabaseTLSFiles{}, fmt.Errorf("storage.database.dsn: %w", err)
		}
		f.ClientCert, f.ClientKey = s.sslcert, s.sslkey
	}
	return f, nil
}
