package dynamic

import (
	"crypto/tls"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// ─── The rewrites themselves ─────────────────────────────────────────────────

func TestStripPostgresRevokeOptions(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		removed []string
	}{
		{"host=h password=p sslcert=/a sslkey='/b c' dbname=d", "host=h password=p dbname=d", []string{"sslcert", "sslkey"}},
		{"sslcert=/a host=h", "host=h", []string{"sslcert"}},
		{"host=h\vpassfile = /a\tdbname=d", "host=h\vdbname=d", []string{"passfile"}},
		{"host=h sslrootcert=/a sslrootcert=/b", "host=h ", []string{"sslrootcert"}},
		// Inside a quoted or escaped value it is not a key: left for the re-check.
		{"host=h password='x sslcert=/a'", "host=h password='x sslcert=/a'", nil},
		{`host=h password=x\ sslcert=/a`, `host=h password=x\ sslcert=/a`, nil},
		{"postgres://u:p@h/d?sslcert=/a&sslmode=require", "postgres://u:p@h/d?sslmode=require", []string{"sslcert"}},
		{"postgres://u:p@h/d?sslmode=require&sslkey=/a&sslpassword=x", "postgres://u:p@h/d?sslmode=require", []string{"sslkey", "sslpassword"}},
		{"postgresql://u:p@h/d?sslc%65rt=/a", "postgresql://u:p@h/d", []string{"sslcert"}},
		// A '?' in the userinfo is not the query (pgconn cuts the userinfo first)...
		{"postgres://u:p?sslcert=x@h/d?application_name=x", "postgres://u:p?sslcert=x@h/d?application_name=x", nil},
		// ...unless a '/' comes before the '@': then pgconn has no userinfo either.
		{"postgres://u:p?sslcert=/a@h/d", "postgres://u:p", []string{"sslcert"}},
	} {
		out, removed, err := stripPostgresRevokeOptions(tc.in)
		if err != nil || out != tc.out || !slices.Equal(removed, tc.removed) {
			t.Errorf("%q: got %q %v %v, want %q %v", tc.in, out, removed, err, tc.out, tc.removed)
		}
	}
	for _, in := range []string{"host=h service=x", "postgres://u:p@h/d?servicefile=/a", "host=h sslcert='open"} {
		if _, _, err := stripPostgresRevokeOptions(in); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
}

// Whatever the rewrite makes of a DSN, the revoke config only ever carries the
// literal sslrootcert=system: anything it left in is refused by the issue-time
// checks it runs again.
func TestParsePostgresRevokeDSNNeverKeepsAFileOption(t *testing.T) {
	isolatePGEnv(t)
	for _, d := range []string{
		"host=h password='x sslcert=/a'",
		`host=h user=u password=x\ sslcert=/a`,
		"postgres://u:p?sslcert=x@h/d?application_name=x",
		"host=h user=u password=p sslcert\v=/a krbsrvname=x",
	} {
		if _, _, err := parsePostgresRevokeDSN(d); !isRefused(err) {
			t.Errorf("%q: want refused, got %v", d, err)
		}
	}
	for _, d := range []string{
		"host=h user=u password=p sslmode=disable sslrootcert=/a",
		"host=h user=u password=p sslrootcert=system",
		"host=h user=u password=p SSLROOTCERT=/a",
		"host=h user=u password=p sslmode=verify-ca sslrootcert=/a",
		"postgres://u:p@h:5432/d?sslrootcert=/a",
		"postgres://u:p@h1:5432,h2:5433/d?sslmode=prefer&sslrootcert=/a",
	} {
		cfg, removed, err := parsePostgresRevokeDSN(d)
		if err != nil || !slices.Equal(removed, []string{"sslrootcert"}) {
			t.Fatalf("%q: %v %v", d, removed, err)
		}
		for _, c := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
			if c == nil || c.InsecureSkipVerify || c.RootCAs == nil || c.ServerName == "" {
				t.Fatalf("%q: a revoke connection does not verify the server: %+v", d, c)
			}
		}
	}
}

func fallbackTLS(cfg *pgx.ConnConfig) []*tls.Config {
	var out []*tls.Config
	for _, f := range cfg.Fallbacks {
		out = append(out, f.TLSConfig)
	}
	return out
}

func TestStripMongoRevokeOptions(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		removed []string
	}{
		{"mongodb://h/admin?tlsCAFile=/a&tls=false&w=1", "mongodb://h/admin?w=1&tls=true", []string{"tlsCAFile"}},
		{"mongodb://h/?a=1;tlsCertificateKeyFile=/k;tlsCertificateKeyFilePassword=x", "mongodb://h/?a=1&tls=true", []string{"tlsCertificateKeyFile"}},
		{"mongodb://u:p%3F@h/admin?ssl=true&tlsCA%46ile=/a", "mongodb://u:p%3F@h/admin?tls=true", []string{"tlsCAFile"}},
		{"mongodb+srv://h/?w=1&tlsCertificateKeyFilePassword=x", "mongodb+srv://h/?w=1&tlsCertificateKeyFilePassword=x", nil},
		{"mongodb://h/admin?w=1", "mongodb://h/admin?w=1", nil},
	} {
		out, removed := stripMongoRevokeOptions(tc.in)
		if out != tc.out || !slices.Equal(removed, tc.removed) {
			t.Errorf("%q: got %q %v, want %q %v", tc.in, out, removed, tc.out, tc.removed)
		}
		if dsn.CheckLocalFileOptions("mongodb", out) != nil {
			t.Errorf("%q: the rewrite still names a file option: %q", tc.in, out)
		}
	}
}

func TestParseMySQLRevokeDSN(t *testing.T) {
	cfg, removed, err := parseMySQLRevokeDSN("u:p@tcp(h:3306)/db?allowAllFiles=true&parseTime=true")
	if err != nil || cfg.AllowAllFiles || !cfg.ParseTime || !slices.Equal(removed, []string{"allowAllFiles"}) {
		t.Fatalf("got %+v %v %v", cfg, removed, err)
	}
	if _, _, err := parseMySQLRevokeDSN("u:p@tcp(h:3306)/db?allowAllFiles=true"); err != nil {
		t.Fatal(err)
	}
}
