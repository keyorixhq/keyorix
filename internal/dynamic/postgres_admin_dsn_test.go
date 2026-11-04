package dynamic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// The postgres admin_dsn is project-admin input. pgx reads files named by
// sslrootcert/sslcert/sslkey/passfile/servicefile/service, and fills what the DSN
// leaves out from the server's own environment (PGPASSWORD, ~/.pgpass, the
// default client certificate under ~/.postgresql). These tests drive dialPostgres
// end to end and look at what pgx actually did or sent.

// isolatePGEnv points every pgx default at an empty home directory and clears the
// PG* variables that could supply a connection setting, so the tests see only
// what they set themselves.
func isolatePGEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, v := range []string{
		"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
		"PGSERVICE", "PGSERVICEFILE", "PGSSLMODE", "PGSSLCERT", "PGSSLKEY",
		"PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLSNI", "PGAPPNAME", "PGCONNECT_TIMEOUT",
		"PGTARGETSESSIONATTRS", "PGSSLNEGOTIATION",
	} {
		t.Setenv(v, "")
	}
	return home
}

// pgCapture is what a rogue postgres server learnt from one client connection.
type pgCapture struct {
	password    string // cleartext password the client sent, "" if none
	clientCerts int    // TLS client certificates the client presented
}

// startPGCaptureServer runs a rogue postgres server that asks every client for a
// cleartext password (and, when serverTLS is set, accepts TLS and requests a
// client certificate) and reports what it received.
func startPGCaptureServer(t *testing.T, serverTLS *tls.Config) (host, port string, got <-chan pgCapture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan pgCapture, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var capt pgCapture
				be := pgproto3.NewBackend(conn, conn)
				for {
					msg, err := be.ReceiveStartupMessage()
					if err != nil {
						return
					}
					if _, ok := msg.(*pgproto3.SSLRequest); ok {
						if serverTLS == nil {
							if _, err := conn.Write([]byte("N")); err != nil {
								return
							}
							continue
						}
						if _, err := conn.Write([]byte("S")); err != nil {
							return
						}
						tc := tls.Server(conn, serverTLS)
						if err := tc.Handshake(); err != nil {
							return
						}
						capt.clientCerts = len(tc.ConnectionState().PeerCertificates)
						conn = tc
						be = pgproto3.NewBackend(conn, conn)
						continue
					}
					break
				}
				be.Send(&pgproto3.AuthenticationCleartextPassword{})
				if err := be.Flush(); err != nil {
					return
				}
				if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
					return
				}
				if msg, err := be.Receive(); err == nil {
					if pm, ok := msg.(*pgproto3.PasswordMessage); ok {
						capt.password = pm.Password
					}
				}
				ch <- capt
				be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "rogue"})
				_ = be.Flush()
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p, ch
}

func dialRogue(t *testing.T, adminDSN string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialPostgres(ctx, adminDSN, true) // private only so the rogue server can sit on loopback
	if conn != nil {
		_ = conn.Close(ctx)
	}
	return err
}

func drain(ch <-chan pgCapture) []pgCapture {
	var out []pgCapture
	for {
		select {
		case c := <-ch:
			out = append(out, c)
		case <-time.After(300 * time.Millisecond):
			return out
		}
	}
}

// Every byte pgx treats as a key separator must also end a key for the textual
// check: "\v" did not (RE2 \s has no \v), and pgx read the file.
func TestPostgresFileOptionsBehindAnySeparatorAreRefused(t *testing.T) {
	home := isolatePGEnv(t)
	garbage := filepath.Join(home, "not-a-cert")
	if err := os.WriteFile(garbage, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := startPGCaptureServer(t, nil)
	base := fmt.Sprintf("host=%s port=%s user=u password=p dbname=d connect_timeout=3", host, port)
	for _, d := range []string{
		base + "\vsslrootcert=" + garbage + " sslmode=verify-full",
		base + " sslrootcert\v=\v" + garbage + " sslmode=verify-full",
		"\vsslkey=" + garbage + " " + base,
		base + "\vpassfile=" + garbage,
		base + "\vservice=x",
		base + "\fsslcert=" + garbage,
	} {
		err := dialRogue(t, d)
		if _, ok := errors.AsType[*dsn.ForbiddenOptionError](err); !ok {
			t.Errorf("%q: want a refused option, got %v (pgx parsed a file option)", d, err)
		}
	}
}

// The allow-list is the structural layer behind the textual check: any key it
// does not list is refused before pgx touches the filesystem.
func TestPostgresAdminDSNKeysOutsideTheAllowListAreRefused(t *testing.T) {
	isolatePGEnv(t)
	host, port, got := startPGCaptureServer(t, nil)
	for _, d := range []string{
		fmt.Sprintf("host=%s port=%s user=u password=p dbname=d krbsrvname=x", host, port),
		fmt.Sprintf("postgres://u:p@%s:%s/d?search_path=x", host, port),
		fmt.Sprintf("postgres://u:p@%s:%s/d?sslpassword=x", host, port),
	} {
		err := dialRogue(t, d)
		if _, ok := errors.AsType[*dsn.ForbiddenOptionError](err); !ok {
			t.Errorf("%q: want a refused option, got %v", d, err)
		}
	}
	if c := drain(got); len(c) != 0 {
		t.Fatalf("the engine connected for a refused DSN: %+v", c)
	}
}

// pgx fills a password the DSN leaves out from PGPASSWORD, a service file or
// ~/.pgpass (also when the DSN sets an empty one). A hostile admin_dsn host would
// then receive the server's own database password.
func TestPostgresEngineNeverSendsTheServersAmbientPassword(t *testing.T) {
	home := isolatePGEnv(t)
	t.Setenv("PGPASSWORD", "ambient-pgpassword")
	if err := os.WriteFile(filepath.Join(home, ".pgpass"), []byte("*:*:*:*:ambient-pgpass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, got := startPGCaptureServer(t, nil)
	base := fmt.Sprintf("host=%s port=%s user=admin dbname=d sslmode=disable connect_timeout=3", host, port)

	for _, d := range []string{
		base,                  // PGPASSWORD
		base + " password=''", // explicit empty password: pgx consults ~/.pgpass
		base + " password=",   // same, unquoted
		// The ambient .pgpass password written into an allowed field must not
		// make the empty password look like the admin's own (REVFIX-3952-3).
		base + " password='' application_name=aaa,admin,ambient-pgpass,changeme",
		base + " password='' dbname=ambient-pgpass",
		fmt.Sprintf("postgres://admin:@%s:%s/d?sslmode=disable&application_name=ambient-pgpass", host, port),
		fmt.Sprintf("postgres://admin@%s:%s/d?sslmode=disable", host, port),
		fmt.Sprintf("postgres://admin:@%s:%s/d?sslmode=disable", host, port),
	} {
		err := dialRogue(t, d)
		if _, ok := errors.AsType[*dsn.ForbiddenOptionError](err); !ok {
			t.Errorf("%q: want refused, got %v", d, err)
		}
	}
	for _, c := range drain(got) {
		if strings.HasPrefix(c.password, "ambient-") {
			t.Fatalf("rogue server received the server's ambient password %q", c.password)
		}
	}

	// Control: a password written in the DSN is used, and wins over PGPASSWORD.
	for _, d := range []string{
		base + " password=dsn-pw",
		fmt.Sprintf("postgres://admin:dsn-pw@%s:%s/d?sslmode=disable", host, port),
		fmt.Sprintf("postgres://admin:dsn%%2Dpw@%s:%s/d?sslmode=disable", host, port),
		fmt.Sprintf("postgres://admin@%s:%s/d?sslmode=disable&password=dsn-pw", host, port),
	} {
		_ = dialRogue(t, d)
		c := drain(got)
		if len(c) != 1 || c[0].password != "dsn-pw" {
			t.Fatalf("%q: want the DSN password sent once, got %+v", d, c)
		}
	}
}

// pgx loads ~/.postgresql/postgresql.crt and .key when both exist and presents
// them to any server that asks. sslcert/sslkey are refused in the DSN, so a
// client certificate can only be the server's own.
func TestPostgresEngineNeverPresentsTheServersDefaultClientCert(t *testing.T) {
	home := isolatePGEnv(t)
	dir := filepath.Join(home, ".postgresql")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSignedPEM(t, "keyorix-server-client-identity")
	if err := os.WriteFile(filepath.Join(dir, "postgresql.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "postgresql.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	srvCertPEM, srvKeyPEM := selfSignedPEM(t, "rogue")
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	host, port, got := startPGCaptureServer(t, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	for _, mode := range []string{"require", "prefer"} {
		_ = dialRogue(t, fmt.Sprintf("host=%s port=%s user=u password=p dbname=d sslmode=%s connect_timeout=3", host, port, mode))
		c := drain(got)
		if len(c) == 0 {
			t.Fatalf("sslmode=%s: rogue server saw no connection", mode)
		}
		for _, x := range c {
			if x.clientCerts != 0 {
				t.Fatalf("sslmode=%s: the server's default client certificate was presented to the target", mode)
			}
		}
	}
}

func selfSignedPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

// Differential guard for the whole separator/encoding class: for every byte in
// every position around a file key, whenever the textual check accepts the DSN,
// pgx with an allow-list that omits the file keys must accept it too. If pgx
// rejects it for a file key, the textual check let a file option through.
// TestLocalFileOptionsCoverTheDrivers only checks key names; this checks how the
// keys are delimited.
func TestPostgresTextualCheckAgreesWithPgxOnEverySeparator(t *testing.T) {
	isolatePGEnv(t)
	// Everything the candidates set except the file keys ("a" is the URL filler).
	allowed := []string{"host", "port", "user", "password", "dbname", "a"}
	const base = "host=h port=5432 user=u password=p dbname=d"
	fileKeys := []string{"sslrootcert", "sslcert", "sslkey", "passfile", "servicefile", "service"}
	for _, key := range fileKeys {
		for b := range 256 {
			s := string([]byte{byte(b)})
			candidates := []string{
				base + s + key + "=/nonexistent/f",
				s + key + "=/nonexistent/f " + base,
				base + " " + key + s + "=/nonexistent/f",
				base + " " + key + "=" + s + "/nonexistent/f",
				base + s + "'" + key + "'=/nonexistent/f",
				"postgres://u:p@h/d?a=b" + s + key + "=/nonexistent/f",
				"postgres://u:p@h/d?a=b&" + url.QueryEscape(s) + key + "=/nonexistent/f",
				"postgres://u:p@h/d?" + key + url.QueryEscape(s) + "=/nonexistent/f",
				"postgresql://u:p@h/d?a=b" + url.QueryEscape("&"+s) + key + "=/nonexistent/f",
			}
			for _, d := range candidates {
				if dsn.CheckLocalFileOptions("postgres", d) != nil {
					continue
				}
				_, err := pgconn.ParseConfigWithOptions(d, pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowed})
				if err != nil && strings.Contains(err.Error(), "ConnStringAllowedKeys") {
					for _, k := range fileKeys {
						if strings.Contains(err.Error(), `"`+k+`"`) {
							t.Errorf("byte 0x%02x: textual check accepted %q but pgx parsed file key %q", b, d, k)
						}
					}
				}
			}
		}
	}
}
