// Oracle 3 (LOCAL INFILE) for MySQL: a hostile server's LOCAL INFILE request must NOT
// make the driver read a local file and send its content back, unless explicitly enabled.
// Keyorix's openMySQLConfig (internal/dynamic/mysql.go) refuses AllowAllFiles and
// registers no reader, so the driver must refuse every LOCAL INFILE request.
//
// This complements #4136's fixed TestMySQLLocalInfile* by (a) planting a real CANARY file
// and asserting its content never reaches the server, and (b) fuzzing the request's
// path/framing. Red proof: TestMySQLLocalInfileCanary_RedProof sets AllowAllFiles=true and
// shows the canary content DOES reach the server, proving the oracle detects the egress.
package mysqlhostile

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

const canaryFileContent = "KX_PP1_LOCAL_INFILE_CANARY_d41d8cd9_secret_file_body"

// plantCanaryFile writes a unique-content file and returns its path.
func plantCanaryFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "canary.txt")
	if err := os.WriteFile(p, []byte(canaryFileContent), 0o600); err != nil {
		t.Fatalf("plant canary: %v", err)
	}
	return p
}

// localInfileRequest builds a LOCAL INFILE request packet (0xfb + path) at seq 1.
func localInfileRequest(path string) []byte {
	return frame(1, append([]byte{0xfb}, []byte(path)...))
}

// capturingServer plays a handshake, reads one COM_QUERY, sends req, then records every
// subsequent byte the client writes into *captured (the file-transfer response, if any).
func capturingServer(t *testing.T, req []byte, captured *[]byte, mu *sync.Mutex) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		if err := completeHandshake(c, r); err != nil {
			return
		}
		if _, _, err := readOnePacket(r, capBytes); err != nil { // client COM_QUERY
			return
		}
		if _, err := c.Write(req); err != nil {
			return
		}
		// Record whatever the client sends in response to the LOCAL INFILE request.
		_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				mu.Lock()
				*captured = append(*captured, buf[:n]...)
				mu.Unlock()
			}
			if err != nil {
				break
			}
		}
		_, _ = c.Write(okPacket(2))
	}
}

func runLocalInfile(t *testing.T, req []byte) []byte {
	var captured []byte
	var mu sync.Mutex
	srv := hostile.NewServer(t, capturingServer(t, req, &captured, &mu))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn := openDB(t, srv.Addr())
	defer func() { _ = conn.Close() }()
	_, _ = conn.ExecContext(ctx, "SELECT 1")
	mu.Lock()
	defer mu.Unlock()
	out := make([]byte, len(captured))
	copy(out, captured)
	return out
}

// TestMySQLLocalInfileCanary_NotRead is the oracle: with the default (Keyorix) config the
// driver must not send the canary file's content to the server.
func TestMySQLLocalInfileCanary_NotRead(t *testing.T) {
	path := plantCanaryFile(t)
	captured := runLocalInfile(t, localInfileRequest(path))
	if bytes.Contains(captured, []byte(canaryFileContent)) {
		t.Fatal("ORACLE local-infile: driver sent the canary file content to the server (LOCAL INFILE honoured by default)")
	}
}

// TestMySQLLocalInfileCanary_RedProof proves the oracle is not vacuous: when the driver is
// configured to allow all local files, the SAME request DOES send the canary content.
// (Test-only; openMySQLConfig never enables this — it refuses AllowAllFiles outright.)
func TestMySQLLocalInfileCanary_RedProof(t *testing.T) {
	path := plantCanaryFile(t)
	var captured []byte
	var mu sync.Mutex
	srv := hostile.NewServer(t, capturingServer(t, localInfileRequest(path), &captured, &mu))
	defer srv.Close()

	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = srv.Addr()
	cfg.User = "kxadmin"
	cfg.Passwd = "kxpw"
	cfg.AllowAllFiles = true // the planted defect: exactly what openMySQLConfig refuses
	cfg.Timeout = 2 * time.Second
	cfg.ReadTimeout = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "SELECT 1")
	mu.Lock()
	leaked := bytes.Contains(captured, []byte(canaryFileContent))
	mu.Unlock()
	if !leaked {
		t.Fatal("red proof premise broken: with AllowAllFiles=true the driver should have sent the canary content")
	}
}

// FuzzMySQLLocalInfile fuzzes the LOCAL INFILE request path/framing; the canary content
// must never reach the server under the default config.
func FuzzMySQLLocalInfile(f *testing.F) {
	f.Add([]byte("/etc/passwd"))
	f.Add([]byte("canary.txt"))
	f.Add([]byte{0xfb, 0x00})
	f.Fuzz(func(t *testing.T, pathBytes []byte) {
		// The planted canary path is always offered; the fuzzer also mutates the raw path.
		path := plantCanaryFile(t)
		reqs := [][]byte{
			localInfileRequest(path),
			frame(1, append([]byte{0xfb}, pathBytes...)),
		}
		for _, req := range reqs {
			captured := runLocalInfile(t, req)
			if bytes.Contains(captured, []byte(canaryFileContent)) {
				t.Fatalf("ORACLE local-infile: canary content egressed for request %x", req)
			}
		}
	})
}
