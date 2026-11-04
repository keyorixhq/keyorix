package dynamic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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
		for _, key := range []string{
			"tlsCAFile", "sslCertificateAuthorityFile", "tlsCertificateKeyFile",
			"sslClientCertificateKeyFile", "tlsCertificateFile", "tlsPrivateKeyFile",
		} {
			uri := "mongodb://h/?" + key + "=/nonexistent/f"
			cs, err := connstring.Parse(uri)
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			set := cs.SSLCaFileSet || cs.SSLClientCertificateKeyFileSet || cs.SSLCertificateFileSet || cs.SSLPrivateKeyFileSet
			if !set {
				t.Fatalf("%s: the driver no longer treats it as a file option; update localFileOptions", key)
			}
			if dsn.CheckLocalFileOptions("mongodb", uri) == nil {
				t.Errorf("%s: file option not refused", key)
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

func rogueMySQL(l net.Listener, want string, got chan<- string) {
	c, err := l.Accept()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
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
	var fe *dsn.ForbiddenOptionError
	if !errors.As(err, &fe) {
		t.Fatalf("want ForbiddenOptionError, got %v", err)
	}
	if err := e.Revoke(ctx, d, "kx_dyn_x"); !errors.As(err, &fe) {
		t.Fatalf("Revoke: want ForbiddenOptionError, got %v", err)
	}
	select {
	case s := <-got:
		t.Fatalf("rogue server received %q; the engine must not even connect", s)
	case <-time.After(500 * time.Millisecond):
	}
}
