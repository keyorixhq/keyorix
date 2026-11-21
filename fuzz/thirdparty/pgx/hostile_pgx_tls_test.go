// Oracle 2 (TLS never silently downgrades) for pgx, with its red proof.
//
// Grounding: Keyorix builds its pgx connection config via config.ResolvePostgresConnConfig
// (internal/config/postgres_dsn.go), which sets the operator's sslmode and, for required
// modes, refuses to start unless the resolved TLS config verifies (finalTLSMismatch). At
// the DRIVER level, sslmode=require makes pgx reject a server that answers 'N' to its
// SSLRequest — it must NOT fall back to plaintext. This test asserts that driver behaviour
// (the mode Keyorix passes through unchanged for required modes).
//
// What this does NOT cover: Keyorix's own finalTLSMismatch / CA-pinning check in
// ResolvePostgresConnConfig — that is a storage-layer guard exercised by
// internal/storage/factory_postgres_tls_test.go, not reachable from this driver-level
// harness. This test covers only the pgx driver's refusal to downgrade under sslmode=require.
package pgxhostile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/pgxlimits"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// nDeclineTLSThenServe plays a server that answers 'N' to SSLRequest (declines TLS) and
// then, if the client proceeds in plaintext, completes a trust-auth handshake. A client
// that required TLS must error at the 'N' and never reach the plaintext handshake.
func nDeclineTLSThenServe(c net.Conn) {
	// First client message: under a TLS-capable sslmode it is the 4-byte SSLRequest
	// (magic 80877103); under sslmode=disable it is the StartupMessage directly.
	msg, err := hostile.ReadClientStartup(c, capBytes)
	if err != nil {
		return
	}
	isSSLRequest := len(msg) == 4 && msg[0] == 0x04 && msg[1] == 0xd2 && msg[2] == 0x16 && msg[3] == 0x2f
	if isSSLRequest {
		if _, err := c.Write([]byte("N")); err != nil { // decline TLS
			return
		}
		// A plaintext-permitted client now sends its StartupMessage.
		if _, err := hostile.ReadClientStartup(c, capBytes); err != nil {
			return
		}
	}
	// msg was already the StartupMessage (sslmode=disable) or we just read it; serve success.
	writeAll(c, cannedHandshake)
	drainBriefly(c)
}

func connectWithSSLMode(t *testing.T, addr, sslmode string) error {
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig("host=" + host + " port=" + port + " user=kx dbname=kx password=p sslmode=" + sslmode)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// Fuzz the configuration that ships: the same per-message bound the production dial path sets.
	pgxlimits.Apply(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

// TestPgxTLSRequireRejectsPlaintext is the oracle: under sslmode=require, a server that
// declines TLS ('N') makes ConnectConfig fail — the client never proceeds in plaintext.
func TestPgxTLSRequireRejectsPlaintext(t *testing.T) {
	srv := hostile.NewServer(t, nDeclineTLSThenServe)
	defer srv.Close()
	if err := connectWithSSLMode(t, srv.Addr(), "require"); err == nil {
		t.Fatal("ORACLE TLS-downgrade: sslmode=require connected to a server that declined TLS (silent plaintext downgrade)")
	}
}

// TestPgxTLSRequireRejectsPlaintext_RedProof proves the oracle is not vacuous: the SAME
// hostile server DOES complete a plaintext connection when the config is downgraded to
// sslmode=disable (the planted defect — a downgrade). Only the sslmode=require setting
// blocks the plaintext path; this is what the oracle above relies on. (Never committed as
// a production change: this is a test-only demonstration of the downgrade the oracle catches.)
func TestPgxTLSRequireRejectsPlaintext_RedProof(t *testing.T) {
	srv := hostile.NewServer(t, nDeclineTLSThenServe)
	defer srv.Close()
	if err := connectWithSSLMode(t, srv.Addr(), "disable"); err != nil {
		t.Fatalf("red proof premise broken: sslmode=disable should connect in plaintext to this server, got %v", err)
	}
	// With sslmode=disable the connection proceeds in plaintext against the same 'N'-answering
	// server — demonstrating exactly the downgrade that sslmode=require (the oracle) prevents.
}
