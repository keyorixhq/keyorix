// Oracle 2 (TLS never silently downgrades) for MySQL, with its red proof.
//
// Grounding: Keyorix does NOT itself force tls= for a dynamic MySQL admin DSN
// (guard.RequireTLS is wired only for mongodb/redis — internal/dynamic/*.go); for MySQL
// it passes the operator's DSN tls= setting through to the driver unchanged. So this
// oracle is CONDITIONAL on the operator having selected the required mode (tls=true / a
// TLS config): under that config, a server whose greeting clears the CLIENT_SSL capability
// flag must make the connection FAIL — the driver must not fall back to plaintext.
//
// What this does NOT cover: certificate / hostname verification (the config here uses
// InsecureSkipVerify so the test needs no PKI), and the operator-DSN parsing that decides
// whether tls= is set — only the driver's refusal to downgrade when TLS is required.
package mysqlhostile

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// greetingServer plays the server side of a native-password handshake. The greeting()
// built by this package advertises serverCapabilities, which deliberately does NOT include
// CLIENT_SSL (0x0800) — so a TLS-requiring client must refuse.
func greetingServer(c net.Conn) {
	r := bufio.NewReader(c)
	if err := completeHandshake(c, r); err != nil {
		return
	}
	// Answer any post-handshake command (e.g. COM_PING) with OK so a plaintext client
	// (the red proof) actually connects; a TLS-requiring client never reaches here.
	for {
		if _, _, err := readOnePacket(r, capBytes); err != nil {
			return
		}
		if _, err := c.Write(okPacket(1)); err != nil {
			return
		}
	}
}

func pingWithTLS(t *testing.T, addr string, requireTLS bool) error {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.User = "kxadmin"
	cfg.Passwd = "kxpw"
	cfg.Timeout = 2 * time.Second
	cfg.ReadTimeout = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	if requireTLS {
		cfg.TLS = &tls.Config{InsecureSkipVerify: true, ServerName: "kx"} //nolint:gosec // test-only; this oracle checks downgrade refusal, not cert verification
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

// TestMySQLTLSRequiredRejectsNoSSLFlag is the oracle: with TLS required, a server that does
// not advertise CLIENT_SSL makes the connection fail (no silent plaintext downgrade).
func TestMySQLTLSRequiredRejectsNoSSLFlag(t *testing.T) {
	srv := hostile.NewServer(t, greetingServer)
	defer srv.Close()
	if err := pingWithTLS(t, srv.Addr(), true); err == nil {
		t.Fatal("ORACLE TLS-downgrade: TLS-required client connected to a server that cleared the SSL flag (silent plaintext downgrade)")
	}
}

// TestMySQLTLSRequiredRejectsNoSSLFlag_RedProof proves the oracle is not vacuous: the SAME
// server DOES complete a plaintext connection when TLS is not required. Only the TLS-required
// setting blocks the plaintext path — exactly what the oracle relies on.
func TestMySQLTLSRequiredRejectsNoSSLFlag_RedProof(t *testing.T) {
	srv := hostile.NewServer(t, greetingServer)
	defer srv.Close()
	if err := pingWithTLS(t, srv.Addr(), false); err != nil {
		t.Fatalf("red proof premise broken: a plaintext client should connect to this server, got %v", err)
	}
}
