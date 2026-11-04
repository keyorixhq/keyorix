package dsn

import (
	"errors"
	"testing"
)

func TestCheckLocalFileOptions(t *testing.T) {
	cases := []struct {
		name, backend, dsn string
		want               string // "" = allowed
	}{
		{"mysql plain", "mysql", "u:p@tcp(db.example.com:3306)/app?tls=true", ""},
		{"mysql allowAllFiles", "mysql", "u:p@tcp(db.example.com:3306)/app?allowAllFiles=true", "allowallfiles"},
		{"mysql allowAllFiles false still refused", "mysql", "u:p@tcp(h)/app?timeout=3s&allowAllFiles=false", "allowallfiles"},
		{"mysql mixed case", "mysql", "u:p@tcp(h)/app?ALLOWALLFILES=1", "allowallfiles"},
		{"mysql percent-encoded key", "mysql", "u:p@tcp(h)/app?allow%41llFiles=true", "allowallfiles"},
		{"mysql password named like option is fine", "mysql", "u:allowAllFiles@tcp(h)/app", ""},
		{"mongo plain", "mongodb", "mongodb://u:p@h/?tls=true&authSource=admin", ""},
		{"mongo tlsCAFile", "mongodb", "mongodb://h/?tls=true&tlsCAFile=/etc/ca.pem", "tlscafile"},
		{"mongo ssl alias", "mongodb", "mongodb://h/?ssl=true&sslCertificateAuthorityFile=/x", "sslcertificateauthorityfile"},
		{"mongo cert key file", "mongodb", "mongodb://h/?tlsCertificateKeyFile=/x", "tlscertificatekeyfile"},
		{"mongo legacy client cert", "mongodb", "mongodb://h/?sslClientCertificateKeyFile=/x", "sslclientcertificatekeyfile"},
		{"mongo semicolon separator", "mongodb", "mongodb://h/?tls=true;tlsPrivateKeyFile=/x", "tlsprivatekeyfile"},
		{"mongo tlsCertificateFile", "mongodb", "mongodb://h/?tlsCertificateFile=/x", "tlscertificatefile"},
		{"mongo oidc", "mongodb", "mongodb://u@h/?tls=true&authMechanism=MONGODB-OIDC&authMechanismProperties=ENVIRONMENT:k8s", "authmechanism=mongodb-oidc"},
		{"mongo oidc lower", "mongodb", "mongodb://u@h/?authmechanism=mongodb-oidc", "authmechanism=mongodb-oidc"},
		{"mongo aws", "mongodb", "mongodb://h/?authMechanism=MONGODB-AWS", "authmechanism=mongodb-aws"},
		{"mongo gssapi", "mongodb", "mongodb://h/?authMechanism=GSSAPI", "authmechanism=gssapi"},
		{"mongo percent-encoded value", "mongodb", "mongodb://h/?authMechanism=MONGODB%2DOIDC", "authmechanism=mongodb-oidc"},
		{"mongo scram is fine", "mongodb", "mongodb://u:p@h/?tls=true&authMechanism=SCRAM-SHA-256&authSource=admin", ""},
		{"pg url plain", "postgres", "postgres://u:p@h:5432/db?sslmode=verify-full", ""},
		{"pg url sslrootcert", "postgres", "postgres://u:p@h/db?sslrootcert=/etc/ca.pem", "sslrootcert"},
		{"pg url sslkey", "postgres", "postgresql://u@h/db?sslmode=require&sslkey=/k&sslcert=/c", "sslkey"},
		{"pg kv sslcert", "postgres", "host=h user=u sslcert=/c", "sslcert"},
		{"pg kv quoted", "postgres", "host=h user=u 'sslrootcert'=/c", "sslrootcert"},
		{"pg kv mixed case", "postgres", "host=h SSLRootCert=/c", "sslrootcert"},
		{"pg passfile", "postgres", "host=h passfile=/root/.pgpass", "passfile"},
		{"pg servicefile", "postgres", "host=h servicefile=/x", "servicefile"},
		{"pg service", "postgres", "service=prod", "service"},
		{"pg url percent key", "postgres", "postgres://u@h/db?ssl%72ootcert=/x", "sslrootcert"},
		{"pg sslmode alone is fine", "postgres", "host=h sslmode=disable", ""},
		{"redis not checked", "redis", "rediss://h:6379/0?tlscafile=/x", ""},
		{"unknown backend not checked", "aws-sts", "tlscafile=/x", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckLocalFileOptions(tc.backend, tc.dsn)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var fe *ForbiddenOptionError
			if !errors.As(err, &fe) {
				t.Fatalf("want ForbiddenOptionError %q, got %v", tc.want, err)
			}
			if fe.Option != tc.want || fe.Backend != tc.backend {
				t.Fatalf("got %+v, want option %q", fe, tc.want)
			}
		})
	}
}

func TestForbiddenOptionErrorNamesOnlyTheOption(t *testing.T) {
	err := CheckLocalFileOptions("mysql", "root:hunter2@tcp(10.0.0.5:3306)/secretdb?allowAllFiles=true")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, leak := range []string{"hunter2", "10.0.0.5", "secretdb", "root"} {
		if contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func FuzzCheckLocalFileOptionsNeverPanics(f *testing.F) {
	f.Add("mysql", "u:p@tcp(h)/db?allowAllFiles=true")
	f.Add("postgres", "host=h 'sslkey'=/x")
	f.Add("mongodb", "mongodb://h/?tlsCAFile=%2Fx")
	f.Fuzz(func(t *testing.T, backend, dsn string) {
		_ = CheckLocalFileOptions(backend, dsn)
	})
}
