package dynamic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
)

const refusedOptionTestTimeout = 15 * time.Second

func refusedOptionContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), refusedOptionTestTimeout)
	t.Cleanup(cancel)
	return ctx
}

func requireForbiddenOption(t *testing.T, err error) {
	t.Helper()
	var fe *dsn.ForbiddenOptionError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForbiddenOptionError, got %v", err)
	}
}

// fakePostgresTarget answers startup and every simple query, and records the
// simple queries. Extended-protocol statements are answered with an error, which
// Revoke's best-effort steps ignore.
type fakePostgresTarget struct {
	addr  net.Addr
	mu    sync.Mutex
	stmts []string
	conns int
}

func startFakePostgres(t *testing.T) *fakePostgresTarget {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := &fakePostgresTarget{addr: l.Addr()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePostgresTarget) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	b := pgproto3.NewBackend(c, c)
	if _, err := b.ReceiveStartupMessage(); err != nil {
		return
	}
	b.Send(&pgproto3.AuthenticationOk{})
	b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if b.Flush() != nil {
		return
	}
	for {
		msg, err := b.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.stmts = append(f.stmts, m.String)
			f.mu.Unlock()
			b.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "0A000", Message: "unsupported by fake"})
		case *pgproto3.Sync:
			b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		}
		if b.Flush() != nil {
			return
		}
	}
}

func (f *fakePostgresTarget) snapshot() (conns int, stmts []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns, slices.Clone(f.stmts)
}

func (f *fakePostgresTarget) port() int { return f.addr.(*net.TCPAddr).Port }

func TestPostgresRevoke_StoredConfigWithRefusedOptions(t *testing.T) {
	cases := map[string]func(port int) string{
		"keyword/value": func(port int) string {
			return fmt.Sprintf("host=127.0.0.1 port=%d user=admin password=pw dbname=app sslmode=disable sslrootcert=/nonexistent/ca.pem sslcert=/nonexistent/c.pem sslkey=/nonexistent/k.pem passfile=/nonexistent/pw", port)
		},
		"url": func(port int) string {
			return fmt.Sprintf("postgres://admin:pw@127.0.0.1:%d/app?sslmode=disable&sslrootcert=/nonexistent/ca.pem&passfile=/nonexistent/pw", port)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			target := startFakePostgres(t)
			e := &PostgresEngine{allowPrivateNetwork: true}
			ctx := refusedOptionContext(t)
			adminDSN := build(target.port())

			_, _, err := e.Issue(ctx, adminDSN, "", time.Minute)
			requireForbiddenOption(t, err)
			requireForbiddenOption(t, e.Renew(ctx, adminDSN, "kx_dyn_x", time.Now().Add(time.Hour)))
			if conns, _ := target.snapshot(); conns != 0 {
				t.Fatalf("Issue and Renew must refuse before connecting, saw %d connection(s)", conns)
			}

			if err := e.Revoke(ctx, adminDSN, "kx_dyn_x"); err != nil {
				t.Fatalf("Revoke on a stored config with refused options: %v", err)
			}
			_, stmts := target.snapshot()
			if !slices.ContainsFunc(stmts, func(s string) bool { return strings.HasPrefix(s, `DROP ROLE IF EXISTS "kx_dyn_x"`) }) {
				t.Fatalf("target never saw DROP ROLE; statements: %q", stmts)
			}
		})
	}
}

// These stay refused on Revoke, and must not reach any server: dropping service
// would send the admin password to a host the DSN does not name, and without its
// passfile a DSN has no password to send.
func TestPostgresRevoke_KeepsRefusingWhatChangesTheTargetOrCredential(t *testing.T) {
	target := startFakePostgres(t)
	e := &PostgresEngine{allowPrivateNetwork: true}
	ctx := refusedOptionContext(t)
	for _, d := range []string{
		fmt.Sprintf("host=127.0.0.1 port=%d user=admin password=pw service=prod", target.port()),
		fmt.Sprintf("host=127.0.0.1 port=%d user=admin password=pw servicefile=/nonexistent/s", target.port()),
		fmt.Sprintf("postgres://admin:pw@127.0.0.1:%d/?service=prod", target.port()),
		fmt.Sprintf("host=127.0.0.1 port=%d user=admin sslmode=disable passfile=/nonexistent/pw", target.port()),
		fmt.Sprintf("host=127.0.0.1 port=%d user=admin password=pw sslmode=disable sslnegotiation=direct", target.port()),
	} {
		requireForbiddenOption(t, e.Revoke(ctx, d, "kx_dyn_x"))
	}
	if conns, _ := target.snapshot(); conns != 0 {
		t.Fatalf("a refused Revoke must not connect, saw %d connection(s)", conns)
	}
}

// Removing sslrootcert must not lower what pgx verified, or the admin password
// goes to a server nobody authenticated.
func TestPostgresRevokeDSN_NeverLowersVerification(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	base := "host=db.example.test user=admin password=pw "
	cases := []struct {
		name, in  string
		wantMode  string
		wantChain bool // pgx verifies the chain itself (verify-ca)
		wantName  bool // pgx verifies the host name (verify-full)
	}{
		{name: "require becomes verify-ca", in: base + "sslmode=require sslrootcert=/nonexistent/ca.pem", wantMode: "verify-ca", wantChain: true},
		{name: "verify-ca stays", in: base + "sslmode=verify-ca sslrootcert=/nonexistent/ca.pem", wantMode: "verify-ca", wantChain: true},
		{name: "verify-full stays", in: base + "sslmode=verify-full sslrootcert=/nonexistent/ca.pem", wantMode: "verify-full", wantName: true},
		{name: "system is verify-full", in: base + "sslmode=require sslrootcert=system", wantMode: "verify-full", wantName: true},
		{name: "system with no sslmode", in: base + "sslrootcert=system", wantMode: "verify-full", wantName: true},
		{name: "url require", in: "postgres://admin:pw@db.example.test/app?sslrootcert=/nonexistent/ca.pem&sslmode=require", wantMode: "verify-ca", wantChain: true},
		{name: "last sslmode wins, as in pgx", in: base + "sslmode=disable sslmode=require sslrootcert=/nonexistent/ca.pem", wantMode: "verify-ca", wantChain: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := postgresRevokeDSN(tc.in)
			if err := dsn.CheckLocalFileOptions("postgres", got); err != nil {
				t.Fatalf("rewritten DSN still refused: %v (%q)", err, got)
			}
			cfg, err := parsePostgresAdminDSN(got)
			if err != nil {
				t.Fatalf("parse %q: %v", got, err)
			}
			if !strings.Contains(got, "sslmode="+tc.wantMode) {
				t.Fatalf("want sslmode=%s in %q", tc.wantMode, got)
			}
			if tc.wantChain && cfg.TLSConfig.VerifyPeerCertificate == nil {
				t.Fatalf("%q: chain verification is off", got)
			}
			if tc.wantName && (cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName == "") {
				t.Fatalf("%q: host name verification is off", got)
			}
		})
	}

	t.Run("PGSSLMODE=require from the environment", func(t *testing.T) {
		t.Setenv("PGSSLMODE", "require")
		got := postgresRevokeDSN(base + "sslrootcert=/nonexistent/ca.pem")
		if !strings.Contains(got, "sslmode=verify-ca") {
			t.Fatalf("got %q", got)
		}
	})
}

func TestPostgresRevokeDSN_PreservesEverythingElse(t *testing.T) {
	t.Setenv("PGSSLMODE", "")
	t.Run("a DSN with nothing to strip is byte-identical", func(t *testing.T) {
		for _, d := range []string{
			"host=h  user=a password='p q' sslmode=require",
			"postgres://a:b@h/db?sslmode=require&application_name=x",
			"postgres://a:b@h/db",
		} {
			if got := postgresRevokeDSN(d); got != d {
				t.Errorf("got %q, want %q", got, d)
			}
		}
	})
	t.Run("quoted and escaped values survive", func(t *testing.T) {
		in := `host=h user=a password='it\'s a pw' sslrootcert='/no such/ca.pem' application_name=a\ b`
		want := `host=h user=a password='it\'s a pw' application_name=a\ b`
		if got := postgresRevokeDSN(in); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("a question mark in the URL password is not the query", func(t *testing.T) {
		in := "postgres://a:p?w@h/db?passfile=/nonexistent/f&sslmode=require"
		want := "postgres://a:p?w@h/db?sslmode=require"
		if got := postgresRevokeDSN(in); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("an unparsable DSN is left for the connect path to refuse", func(t *testing.T) {
		in := "host=h sslrootcert='unterminated"
		if got := postgresRevokeDSN(in); got != in {
			t.Fatalf("got %q", got)
		}
		requireForbiddenOption(t, (&PostgresEngine{}).Revoke(context.Background(), in, "kx_dyn_x"))
	})
}

func TestMongoRevoke_StoredConfigWithRefusedOptions(t *testing.T) {
	target := dynamictest.StartFakeMongo(t)
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	ctx := refusedOptionContext(t)
	for _, opts := range []string{
		"tlsCAFile=/nonexistent/ca.pem",
		"tlsCertificateKeyFile=/nonexistent/k.pem&tlsCertificateKeyFilePassword=x",
		"sslCertificateAuthorityFile=/nonexistent/ca.pem;sslClientCertificateKeyFile=/nonexistent/k.pem",
		"tlsCertificateFile=/nonexistent/c.pem&tlsPrivateKeyFile=/nonexistent/k.pem",
		"TLSCAFILE=/nonexistent/ca.pem",
	} {
		uri := fmt.Sprintf("mongodb://%s/?directConnection=true&%s", target.Addr, opts)
		_, _, err := e.Issue(ctx, uri, `{"roles":[]}`, time.Minute)
		requireForbiddenOption(t, err)
		if err := e.Revoke(ctx, uri, "kx_dyn_x"); err != nil {
			t.Fatalf("Revoke with %s: %v", opts, err)
		}
	}
	if got := target.Dropped(); len(got) != 5 {
		t.Fatalf("want 5 dropUser commands, got %q", got)
	}
	if got := target.Created(); len(got) != 0 {
		t.Fatalf("Issue must refuse before createUser, got %q", got)
	}
}

func TestMongoRevoke_KeepsRefusingAmbientCredentials(t *testing.T) {
	target := dynamictest.StartFakeMongo(t)
	e := &MongoEngine{allowPrivateNetwork: true, allowInsecureTransport: true}
	uri := fmt.Sprintf("mongodb://u@%s/?directConnection=true&authMechanism=MONGODB-OIDC&tlsCAFile=/nonexistent/ca.pem", target.Addr)
	requireForbiddenOption(t, e.Revoke(refusedOptionContext(t), uri, "kx_dyn_x"))
	if got := target.Dropped(); len(got) != 0 {
		t.Fatalf("a refused Revoke must not run, got %q", got)
	}
}

func TestMongoRevokeURI(t *testing.T) {
	for in, want := range map[string]string{
		"mongodb://h/?tls=true":                               "mongodb://h/?tls=true",
		"mongodb://h/":                                        "mongodb://h/",
		"mongodb://h/?tlsCAFile=/f":                           "mongodb://h/",
		"mongodb://h/?tls=true&tlsCAFile=/f&replicaSet=rs":    "mongodb://h/?tls=true&replicaSet=rs",
		"mongodb://h/?tls=true;tlsCAFile=/f":                  "mongodb://h/?tls=true",
		"mongodb://h/?tls%43AFile=/f&tls=true":                "mongodb://h/?tls=true",
		"mongodb+srv://u:p@h/db?tlsCertificateKeyFile=/f&w=1": "mongodb+srv://u:p@h/db?w=1",
	} {
		if got := mongoRevokeURI(in); got != want {
			t.Errorf("mongoRevokeURI(%q) = %q, want %q", in, got, want)
		}
		if err := dsn.CheckLocalFileOptions("mongodb", mongoRevokeURI(in)); err != nil {
			t.Errorf("%q: rewritten URI still refused: %v", in, err)
		}
	}
}

// fakeMySQLTarget answers the first statement with a LOCAL INFILE request for
// wantFile (what a rogue server would do), then OK to everything, and records
// the statements and any file bytes the driver sends back.
type fakeMySQLTarget struct {
	mu       sync.Mutex
	stmts    []string
	received []byte
}

func readMySQLPacket(c net.Conn) (payload []byte, seq byte, err error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, 0, err
	}
	payload = make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
	_, err = io.ReadFull(c, payload)
	return payload, h[3], err
}

func (f *fakeMySQLTarget) serve(l net.Listener, wantFile string) {
	mysqlOK := []byte{0, 0, 0, 2, 0, 0, 0}
	asked := false
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		rogueHandshake(c)
		for {
			p, seq, err := readMySQLPacket(c)
			if err != nil {
				break
			}
			if len(p) > 0 && p[0] == 0x16 { // COM_STMT_PREPARE: refuse, Revoke ignores it
				rogueWrite(c, seq+1, append([]byte{0xff, 0x28, 0x04, '#'}, []byte("42000unsupported by fake")...))
				continue
			}
			if len(p) == 0 || p[0] != 3 {
				rogueWrite(c, seq+1, mysqlOK)
				continue
			}
			f.mu.Lock()
			f.stmts = append(f.stmts, string(p[1:]))
			f.mu.Unlock()
			if asked {
				rogueWrite(c, seq+1, mysqlOK)
				continue
			}
			asked = true
			rogueWrite(c, seq+1, append([]byte{0xfb}, []byte(wantFile)...))
			for {
				d, last, err := readMySQLPacket(c)
				if err != nil {
					break
				}
				seq = last
				if len(d) == 0 {
					break
				}
				f.mu.Lock()
				f.received = append(f.received, d...)
				f.mu.Unlock()
			}
			rogueWrite(c, seq+1, mysqlOK)
		}
		_ = c.Close()
	}
}

func TestMySQLRevoke_StoredConfigWithAllowAllFiles(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "server-secret.yaml")
	if err := os.WriteFile(secret, []byte("master_key: s3cr3t-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	target := &fakeMySQLTarget{}
	go target.serve(l, secret)

	e := &MySQLEngine{allowPrivateNetwork: true}
	ctx := refusedOptionContext(t)
	// The first statement meets the rogue LOCAL INFILE request: that revoke fails
	// and nothing is sent. The revokes after it reach DROP USER.
	rogueDSN := fmt.Sprintf("root:x@tcp(%s)/db?timeout=3s&allowAllFiles=true", l.Addr())
	if err := e.Revoke(ctx, rogueDSN, "kx_dyn_x"); err == nil || !strings.Contains(err.Error(), "is not registered") {
		t.Fatalf("want the driver to refuse the rogue file request, got %v", err)
	}
	for _, opt := range []string{"allowAllFiles=true", "allowAllFiles=false"} {
		adminDSN := fmt.Sprintf("root:x@tcp(%s)/db?timeout=3s&%s", l.Addr(), opt)
		_, _, err = e.Issue(ctx, adminDSN, "", time.Minute)
		requireForbiddenOption(t, err)
		if err := e.Revoke(ctx, adminDSN, "kx_dyn_x"); err != nil {
			t.Fatalf("Revoke with %s: %v", opt, err)
		}
	}

	target.mu.Lock()
	defer target.mu.Unlock()
	if len(target.received) != 0 {
		t.Fatalf("the driver sent %q to a LOCAL INFILE request; a Revoke must never read local files", target.received)
	}
	drops := 0
	for _, s := range target.stmts {
		if strings.HasPrefix(s, "DROP USER IF EXISTS 'kx_dyn_x'") {
			drops++
		}
	}
	if drops != 3 {
		t.Fatalf("want 3 DROP USER statements, saw %q", target.stmts)
	}
}

// A new refused option has to be sorted here: either a Revoke may drop it, or it
// is named as changing the target or credential and stays refused.
func TestEveryRefusedOptionHasARevokeDecision(t *testing.T) {
	staysRefused := map[string]map[string]bool{
		"postgres": {"service": true, "servicefile": true},
		"mongodb":  {},
		"mysql":    {},
	}
	stripped := map[string]func(string) bool{
		"postgres": func(k string) bool { return postgresRevokeStrippedKeys[k] },
		"mongodb":  func(k string) bool { return mongoRevokeStrippedKeys[k] },
		"mysql":    func(k string) bool { return k == "allowallfiles" },
	}
	for backend, isStripped := range stripped {
		keys := dsn.LocalFileOptions(backend)
		if len(keys) == 0 {
			t.Fatalf("%s: no refused options listed; the derivation is broken", backend)
		}
		for _, k := range keys {
			if isStripped(k) == staysRefused[backend][k] {
				t.Errorf("%s option %q needs exactly one decision (strip on revoke, or stay refused)", backend, k)
			}
		}
	}
}

// pgx must keep agreeing with the tokenizer on which values are values.
func TestPostgresKeywordValuePairsAgreesWithPgx(t *testing.T) {
	for _, d := range []string{
		"host=h port=1 user=a password=b",
		"host = h  user\t=\ta password='p q'",
		`host=h user=a password='x\'y' application_name=a\ b`,
		"user=a password=b host=h\vapplication_name=z",
		`host=h user=a password=b application_name=c\`,
		"host=h user=a password='' application_name=",
	} {
		pairs, ok := postgresKeywordValuePairs(d)
		if !ok {
			t.Fatalf("%q: tokenizer refused a DSN pgx accepts", d)
		}
		cfg, err := pgx.ParseConfig(d)
		if err != nil {
			t.Fatalf("%q: pgx: %v", d, err)
		}
		for _, p := range pairs {
			var want string
			switch p.key {
			case "host":
				want = cfg.Host
			case "user":
				want = cfg.User
			case "password":
				want = cfg.Password
			case "port":
				want = fmt.Sprint(cfg.Port)
			case "application_name":
				want = cfg.RuntimeParams["application_name"]
			default:
				t.Fatalf("%q: unexpected key %q", d, p.key)
			}
			if p.value != want {
				t.Errorf("%q: key %s: tokenizer %q, pgx %q", d, p.key, p.value, want)
			}
		}
	}
}
