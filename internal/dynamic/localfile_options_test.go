package dynamic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
)

// The admin_dsn is project-admin input. These tests pin the options that make
// a driver touch the server's disk, against the real drivers in go.mod.

func TestLocalFileOptionsCoverTheDrivers(t *testing.T) {
	t.Run("mongodb", func(t *testing.T) {
		// Every ConnString field named *FileSet is the driver recording that a
		// URI option names a file. Each must have at least one listed key that
		// sets it, so a driver bump that adds a file option fails here until the
		// key is added to localFileOptions. A "File" field without a "FileSet"
		// flag would escape this derivation, so those are rejected outright.
		keysByField := map[string][]string{
			"SSLCaFileSet":                   {"tlsCAFile", "sslCertificateAuthorityFile"},
			"SSLClientCertificateKeyFileSet": {"tlsCertificateKeyFile", "sslClientCertificateKeyFile"},
			"SSLCertificateFileSet":          {"tlsCertificateFile"},
			"SSLPrivateKeyFileSet":           {"tlsPrivateKeyFile"},
		}
		ct := reflect.TypeFor[connstring.ConnString]()
		for f := range ct.Fields() {
			switch {
			case strings.HasSuffix(f.Name, "FileSet"):
				if len(keysByField[f.Name]) == 0 {
					t.Errorf("connstring.ConnString.%s is a new file option with no listed key; add it to localFileOptions and keysByField", f.Name)
				}
			case strings.HasSuffix(f.Name, "File"):
				if _, ok := ct.FieldByName(f.Name + "Set"); !ok {
					t.Errorf("connstring.ConnString.%s looks like a file option without a Set flag; extend this derivation", f.Name)
				}
			}
		}
		for field, keys := range keysByField {
			if _, ok := ct.FieldByName(field); !ok {
				t.Errorf("connstring.ConnString.%s is gone; update keysByField", field)
				continue
			}
			for _, key := range keys {
				uri := "mongodb://h/?" + key + "=/nonexistent/f"
				cs, err := connstring.Parse(uri)
				if err != nil {
					t.Fatalf("%s: %v", key, err)
				}
				if !reflect.Indirect(reflect.ValueOf(cs)).FieldByName(field).Bool() {
					t.Fatalf("%s: the driver no longer sets %s; update keysByField and localFileOptions", key, field)
				}
				if dsn.CheckLocalFileOptions("mongodb", uri) == nil {
					t.Errorf("%s: file option not refused", key)
				}
			}
		}
	})
	t.Run("mongodb ambient-credential mechanisms", func(t *testing.T) {
		for _, mech := range []string{"MONGODB-OIDC", "MONGODB-AWS", "GSSAPI"} {
			uri := "mongodb://u@h/?authMechanism=" + mech
			cs, err := connstring.Parse(uri)
			if err != nil || cs.AuthMechanism != mech {
				t.Fatalf("%s: driver parse: %v %q", mech, err, cs.AuthMechanism)
			}
			if dsn.CheckLocalFileOptions("mongodb", uri) == nil {
				t.Errorf("%s: not refused", mech)
			}
		}
	})
	t.Run("mysql", func(t *testing.T) {
		cfg, err := mysql.ParseDSN("u:p@tcp(h:3306)/db?allowAllFiles=true")
		if err != nil || !cfg.AllowAllFiles {
			t.Fatalf("driver stopped honouring allowAllFiles: %v", err)
		}
		if dsn.CheckLocalFileOptions("mysql", "u:p@tcp(h:3306)/db?allowAllFiles=true") == nil {
			t.Error("allowAllFiles not refused")
		}
	})
	t.Run("postgres", func(t *testing.T) {
		for _, key := range []string{"sslrootcert", "sslcert", "sslkey", "passfile", "servicefile"} {
			d := "host=h sslmode=verify-full " + key + "=/nonexistent/f"
			if key == "servicefile" {
				d = "service=s servicefile=/nonexistent/f"
			}
			_, err := pgx.ParseConfig(d)
			if err == nil || !strings.Contains(err.Error(), "/nonexistent/f") {
				// passfile with a missing file is tolerated by pgx; it is still read.
				if key != "passfile" {
					t.Fatalf("%s: pgx did not try to read the file (%v); update localFileOptions", key, err)
				}
			}
			if dsn.CheckLocalFileOptions("postgres", d) == nil {
				t.Errorf("%s: not refused", key)
			}
		}
	})
}

// Rogue MySQL server: answers the first statement with a LOCAL INFILE request.
func rogueWrite(c net.Conn, seq byte, p []byte) {
	h := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}
	_, _ = c.Write(append(h, p...))
}

func rogueRead(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	b := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
	_, err := io.ReadFull(c, b)
	return b, err
}

func rogueHandshake(c net.Conn) {
	hs := []byte{10}
	hs = append(hs, []byte("5.7.0-rogue\x00")...)
	hs = append(hs, 1, 0, 0, 0)
	hs = append(hs, []byte("abcdefgh\x00")...)
	caps := uint32(0x0200 | 0x8000 | 0x80000 | 0x0008 | 0x0001 | 0x00800000 | 0x00020000)
	hs = append(hs, byte(caps), byte(caps>>8), 33, 2, 0, byte(caps>>16), byte(caps>>24), 21)
	hs = append(hs, make([]byte, 10)...)
	hs = append(hs, []byte("ijklmnopqrst\x00")...)
	hs = append(hs, []byte("mysql_native_password\x00")...)
	rogueWrite(c, 0, hs)
	_, _ = rogueRead(c)
	rogueWrite(c, 2, []byte{0, 0, 0, 2, 0, 0, 0})
}

func rogueMySQL(l net.Listener, want string, got chan<- string) {
	c, err := l.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	rogueHandshake(c)
	for {
		p, err := rogueRead(c)
		if err != nil {
			return
		}
		if len(p) > 0 && p[0] == 3 {
			rogueWrite(c, 1, append([]byte{0xfb}, []byte(want)...))
			var buf []byte
			for {
				d, err := rogueRead(c)
				if err != nil || len(d) == 0 {
					break
				}
				buf = append(buf, d...)
			}
			got <- string(buf)
			rogueWrite(c, 4, []byte{0, 0, 0, 2, 0, 0, 0})
			return
		}
		rogueWrite(c, 1, []byte{0, 0, 0, 2, 0, 0, 0})
	}
}

func TestMySQLEngineNeverSendsLocalFilesToTheServer(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "server-secret.yaml")
	if err := os.WriteFile(secret, []byte("master_key: s3cr3t-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	got := make(chan string, 1)
	go rogueMySQL(l, secret, got)

	e := &MySQLEngine{allowPrivateNetwork: true} // private only so the rogue server can sit on loopback
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := fmt.Sprintf("root:x@tcp(%s)/db?timeout=3s&allowAllFiles=true", l.Addr())
	_, _, err = e.Issue(ctx, d, "", time.Minute)
	if _, ok := errors.AsType[*dsn.ForbiddenOptionError](err); !ok {
		t.Fatalf("want ForbiddenOptionError, got %v", err)
	}
	// Revoke connects without allowAllFiles (#3980); that the file still never
	// reaches the server is TestMySQLRevoke_StoredConfigWithAllowAllFiles.
	select {
	case s := <-got:
		t.Fatalf("rogue server received %q; the engine must not even connect", s)
	case <-time.After(500 * time.Millisecond):
	}
}
