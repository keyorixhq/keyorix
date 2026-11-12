package dynamic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// #3980: a config stored before #3952 may carry an admin_dsn option that the
// drivers would answer by reading a file on the Keyorix server. Issue refuses such
// a DSN; Revoke must still drop the leases already issued from it, with the option
// stripped and without the file ever being read. These tests drive the engines
// end to end against in-process protocol stubs (no live database).

// clientBytes records every byte the client sent on the connections a stub
// accepted, and how many connections it accepted.
type clientBytes struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	conns int
}

func (r *clientBytes) wrap(c net.Conn) net.Conn {
	r.mu.Lock()
	r.conns++
	r.mu.Unlock()
	return &recordingConn{Conn: c, rec: r}
}

func (r *clientBytes) contains(s string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Contains(r.buf.Bytes(), []byte(s))
}

func (r *clientBytes) accepted() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns
}

type recordingConn struct {
	net.Conn
	rec *clientBytes
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.mu.Lock()
	c.rec.buf.Write(p[:n])
	c.rec.mu.Unlock()
	return n, err
}

// serve accepts connections on ln until the test ends and hands each one,
// recorded, to handle.
func serve(t *testing.T, ln net.Listener, handle func(net.Conn)) *clientBytes {
	t.Helper()
	rec := &clientBytes{}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(rec.wrap(c))
		}
	}()
	return rec
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// serverFiles writes a TLS server certificate for the stubs, plus files a
// stripped option may point at. caFile holds the stub's own certificate, so a
// driver that READ it would trust the stub and the handshake would succeed.
type serverFiles struct {
	tls     *tls.Config
	caFile  string
	garbage string
}

func newServerFiles(t *testing.T) serverFiles {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedPEM(t, "127.0.0.1")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "server-secret.yaml")
	if err := os.WriteFile(garbage, []byte("master_key: s3cr3t-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return serverFiles{
		tls:     &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		caFile:  ca,
		garbage: garbage,
	}
}

func isRefused(err error) bool {
	_, ok := errors.AsType[*dsn.ForbiddenOptionError](err)
	return ok
}

func revokeCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ─── Postgres ────────────────────────────────────────────────────────────────

func TestPostgresRevokeStripsLocalFileOptions(t *testing.T) {
	isolatePGEnv(t)
	f := newServerFiles(t)
	ln := listenLoopback(t)
	rec := serve(t, ln, handleFakePGConn)
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	base := fakePGDSN(host, port)
	e := &PostgresEngine{allowPrivateNetwork: true}

	for _, d := range []string{
		base + " sslcert=" + f.garbage + " sslkey=" + f.garbage,
		base + " sslkey='" + f.garbage + "' sslpassword='x y'",
		base + " passfile=" + f.garbage,
		base + "\vSSLCERT = " + f.garbage,
		fmt.Sprintf("postgres://admin:pw@%s:%s/testdb?sslmode=disable&sslcert=%s&sslkey=%s&sslpassword=x", host, port, f.garbage, f.garbage),
		fmt.Sprintf("postgresql://admin:pw@%s:%s/testdb?passfile=%s&sslmode=disable", host, port, f.garbage),
	} {
		role := "kx_dyn_" + fmt.Sprint(rec.accepted())
		if err := e.Revoke(revokeCtx(t), d, role); err != nil {
			t.Fatalf("%q: revoke of an existing lease failed: %v", d, err)
		}
		if !rec.contains(`DROP ROLE IF EXISTS "` + role + `"`) {
			t.Fatalf("%q: revoke returned nil but the target never saw DROP ROLE %s", d, role)
		}
	}
}

// sslrootcert is replaced by the system trust store with full verification, so
// the revoke never trusts less than the stored DSN did, and never falls back to
// plaintext. caFile is the stub's own certificate: had pgx read it, verify-ca
// would succeed and the stub would receive the password.
func TestPostgresRevokeWithSSLRootCertFailsClosed(t *testing.T) {
	isolatePGEnv(t)
	f := newServerFiles(t)
	tlsHost, tlsPort, tlsGot := startPGCaptureServer(t, f.tls)
	plainHost, plainPort, plainGot := startPGCaptureServer(t, nil)
	e := &PostgresEngine{allowPrivateNetwork: true}

	for _, tc := range []struct {
		dsn string
		got <-chan pgCapture
	}{
		{fmt.Sprintf("host=%s port=%s user=u password=p dbname=d connect_timeout=3 sslmode=verify-ca sslrootcert=%s", tlsHost, tlsPort, f.caFile), tlsGot},
		{fmt.Sprintf("host=%s port=%s user=u password=p dbname=d connect_timeout=3 sslmode=require sslrootcert=%s", tlsHost, tlsPort, f.caFile), tlsGot},
		{fmt.Sprintf("postgres://u:p@%s:%s/d?connect_timeout=3&sslrootcert=%s", tlsHost, tlsPort, f.caFile), tlsGot},
		// A target without TLS: prefer/allow/disable would talk plaintext, the
		// stripped revoke must not.
		{fmt.Sprintf("host=%s port=%s user=u password=p dbname=d connect_timeout=3 sslmode=prefer sslrootcert=%s", plainHost, plainPort, f.caFile), plainGot},
		{fmt.Sprintf("host=%s port=%s user=u password=p dbname=d connect_timeout=3 sslmode=disable sslrootcert=%s", plainHost, plainPort, f.caFile), plainGot},
	} {
		err := e.Revoke(revokeCtx(t), tc.dsn, "kx_dyn_x")
		if err == nil || isRefused(err) {
			t.Fatalf("%q: want a TLS failure against the system trust store, got %v", tc.dsn, err)
		}
		t.Logf("revoke_failed reason: %v", err)
		if !strings.Contains(err.Error(), "sslrootcert") {
			t.Errorf("%q: the failure must name the stripped option: %v", tc.dsn, err)
		}
		if c := drain(tc.got); len(c) != 0 {
			t.Fatalf("%q: the target received a password (CA file read or plaintext fallback): %+v", tc.dsn, c)
		}
	}
}

// service/servicefile replace the target itself, so they cannot be stripped.
func TestPostgresRevokeStillRefusesServiceOptions(t *testing.T) {
	isolatePGEnv(t)
	f := newServerFiles(t)
	ln := listenLoopback(t)
	rec := serve(t, ln, handleFakePGConn)
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	e := &PostgresEngine{allowPrivateNetwork: true}
	for _, d := range []string{
		fakePGDSN(host, port) + " service=prod",
		fakePGDSN(host, port) + " servicefile=" + f.garbage,
		fmt.Sprintf("postgres://admin:pw@%s:%s/testdb?sslmode=disable&service=prod", host, port),
	} {
		err := e.Revoke(revokeCtx(t), d, "kx_dyn_x")
		if !isRefused(err) {
			t.Fatalf("%q: want refused, got %v", d, err)
		}
	}
	if n := rec.accepted(); n != 0 {
		t.Fatalf("the engine connected %d time(s) for a refused DSN", n)
	}
}

// Issue and Renew keep the #3952 refusal: only Revoke strips.
func TestPostgresIssueAndRenewStillRefuseStrippableOptions(t *testing.T) {
	isolatePGEnv(t)
	f := newServerFiles(t)
	ln := listenLoopback(t)
	rec := serve(t, ln, handleFakePGConn)
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	e := &PostgresEngine{allowPrivateNetwork: true}
	for _, d := range []string{
		fakePGDSN(host, port) + " sslcert=" + f.garbage + " sslkey=" + f.garbage,
		fakePGDSN(host, port) + " passfile=" + f.garbage,
		fakePGDSN(host, port) + " sslrootcert=" + f.caFile,
	} {
		if _, _, err := e.Issue(revokeCtx(t), d, "", time.Minute); !isRefused(err) {
			t.Fatalf("Issue %q: want refused, got %v", d, err)
		}
		if err := e.Renew(revokeCtx(t), d, "kx_dyn_x", time.Now().Add(time.Hour)); !isRefused(err) {
			t.Fatalf("Renew %q: want refused, got %v", d, err)
		}
	}
	if n := rec.accepted(); n != 0 {
		t.Fatalf("Issue/Renew connected %d time(s) for a refused DSN", n)
	}
}

// ─── MySQL ───────────────────────────────────────────────────────────────────

func startRecordingMySQL(t *testing.T) (addr string, rec *clientBytes) {
	t.Helper()
	ln := listenLoopback(t)
	rec = serve(t, ln, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		if sendMySQLHandshake(c) {
			handleMySQLCommands(c, -1)
		}
	})
	return ln.Addr().String(), rec
}

func TestMySQLRevokeStripsAllowAllFiles(t *testing.T) {
	addr, rec := startRecordingMySQL(t)
	e := &MySQLEngine{allowPrivateNetwork: true}
	for i, d := range []string{
		"admin:pass@tcp(" + addr + ")/testdb?allowAllFiles=true",
		"admin:pass@tcp(" + addr + ")/testdb?timeout=5s&allowAllFiles=true&parseTime=true",
		"admin:pass@tcp(" + addr + ")/testdb?AllowAllFiles=true",
	} {
		role := fmt.Sprintf("kx_dyn_m%d", i)
		if err := e.Revoke(revokeCtx(t), d, role); err != nil {
			t.Fatalf("%q: revoke of an existing lease failed: %v", d, err)
		}
		if !rec.contains("DROP USER IF EXISTS '" + role + "'@'%'") {
			t.Fatalf("%q: revoke returned nil but the target never saw DROP USER %s", d, role)
		}
		if _, _, err := e.Issue(revokeCtx(t), d, "", time.Minute); !isRefused(err) {
			t.Fatalf("Issue %q: want refused, got %v", d, err)
		}
	}
}

// ─── MongoDB ─────────────────────────────────────────────────────────────────

// startRecordingMongo runs the fake MongoDB server of dynamic_s25_test.go, over
// TLS when serverTLS is set.
func startRecordingMongo(t *testing.T, serverTLS *tls.Config) (hostPort string, rec *clientBytes) {
	t.Helper()
	ln := listenLoopback(t)
	addr := ln.Addr().String()
	if serverTLS != nil {
		ln = tls.NewListener(ln, serverTLS)
	}
	rec = serve(t, ln, func(c net.Conn) {
		// The recorder wraps the TLS conn, so it sees decrypted commands.
		handleFakeMongoConn(c)
	})
	return addr, rec
}

func TestMongoRevokeStripsTLSFileOptions(t *testing.T) {
	f := newServerFiles(t)
	addr, rec := startRecordingMongo(t, f.tls)
	// TLS stays required (allowInsecureTransport false); tlsInsecure only lets the
	// stub's self-signed certificate through. The file options point at a file
	// that is not a certificate: a driver that read it would fail before dialing.
	e := &MongoEngine{allowPrivateNetwork: true}
	opts := "directConnection=true&serverSelectionTimeoutMS=3000&tlsInsecure=true"
	for i, q := range []string{
		"tlsCAFile=" + f.garbage,
		"tlsCertificateKeyFile=" + f.garbage + "&tlsCertificateKeyFilePassword=x",
		"sslCertificateAuthorityFile=" + f.garbage + ";sslClientCertificateKeyFile=" + f.garbage,
		"tlsCertificateFile=" + f.garbage + "&tlsPrivateKeyFile=" + f.garbage,
		"TLSCAFILE=" + f.garbage,
	} {
		uri := "mongodb://" + addr + "/admin?" + opts + "&" + q
		role := fmt.Sprintf("kx_dyn_g%d", i)
		if err := e.Revoke(revokeCtx(t), uri, role); err != nil {
			t.Fatalf("%q: revoke of an existing lease failed: %v", uri, err)
		}
		if !rec.contains("dropUser") || !rec.contains(role) {
			t.Fatalf("%q: revoke returned nil but the target never saw dropUser %s", uri, role)
		}
		if _, _, err := e.Issue(revokeCtx(t), uri, "", time.Minute); !isRefused(err) {
			t.Fatalf("Issue %q: want refused, got %v", uri, err)
		}
	}
}

// tlsCAFile is replaced by the system trust store, never by "no TLS". caFile is
// the stub's own certificate: had the driver read it, the handshake would pass.
func TestMongoRevokeWithTLSCAFileFailsClosed(t *testing.T) {
	f := newServerFiles(t)
	tlsAddr, tlsRec := startRecordingMongo(t, f.tls)
	plainAddr, plainRec := startRecordingMongo(t, nil)
	opts := "directConnection=true&serverSelectionTimeoutMS=1500"
	for _, tc := range []struct {
		uri string
		rec *clientBytes
	}{
		{"mongodb://" + tlsAddr + "/admin?" + opts + "&tlsCAFile=" + f.caFile, tlsRec},
		// Even with plaintext allowed install-wide and tls=false written, a DSN
		// that named a CA file talked TLS; the stripped revoke still must.
		{"mongodb://" + plainAddr + "/admin?" + opts + "&tlsCAFile=" + f.caFile, plainRec},
		{"mongodb://" + plainAddr + "/admin?" + opts + "&tls=false&sslCertificateAuthorityFile=" + f.caFile, plainRec},
	} {
		e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
		err := e.Revoke(revokeCtx(t), tc.uri, "kx_dyn_x")
		if err == nil || isRefused(err) {
			t.Fatalf("%q: want a TLS failure against the system trust store, got %v", tc.uri, err)
		}
		t.Logf("revoke_failed reason: %v", err)
		if !strings.Contains(strings.ToLower(err.Error()), "cafile") && !strings.Contains(err.Error(), "CertificateAuthorityFile") {
			t.Errorf("%q: the failure must name the stripped option: %v", tc.uri, err)
		}
		if tc.rec.contains("dropUser") {
			t.Fatalf("%q: dropUser reached the target (CA file read or plaintext fallback)", tc.uri)
		}
	}
}

// Ambient-credential mechanisms change who authenticates, so they cannot be
// stripped.
func TestMongoRevokeStillRefusesAmbientCredentialMechanisms(t *testing.T) {
	addr, rec := startRecordingMongo(t, nil)
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	for _, mech := range []string{"MONGODB-AWS", "MONGODB-OIDC", "GSSAPI"} {
		uri := "mongodb://u@" + addr + "/admin?directConnection=true&authMechanism=" + mech
		if err := e.Revoke(revokeCtx(t), uri, "kx_dyn_x"); !isRefused(err) {
			t.Fatalf("%q: want refused, got %v", uri, err)
		}
	}
	if n := rec.accepted(); n != 0 {
		t.Fatalf("the engine connected %d time(s) for a refused DSN", n)
	}
}

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
