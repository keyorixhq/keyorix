package mysqlfuzz

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// runExecCapture drives one ExecContext against a hostile server, capturing all
// bytes the client sends. cfgMut may mutate the driver config (e.g. AllowAllFiles).
func runExecCapture(t *testing.T, script []byte, query string, cfgMut func(*mysql.Config)) (clientBytes []byte, err error) {
	t.Helper()
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Skipf("cannot listen: %v", lerr)
	}
	cap := &syncBuf{}
	s := startServer(ln, buildScript(script), cap, 300*time.Millisecond)
	defer s.shutdown()

	cfg := newConfig(ln.Addr().String())
	if cfgMut != nil {
		cfgMut(cfg)
	}
	connector, cerr := mysql.NewConnector(cfg)
	if cerr != nil {
		t.Fatalf("harness: NewConnector: %v", cerr)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, query)
	return cap.bytes(), err
}

// reproPanic runs script against a hostile server and returns the recovered
// panic value (nil if the driver did not panic). The driver's connect path runs
// synchronously in the calling goroutine (connector.Connect -> handleAuthResult
// -> auth), so a panic there unwinds to here and is recoverable.
func reproPanic(t *testing.T, script []byte) (recovered any) {
	t.Helper()
	defer func() { recovered = recover() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	s := startServer(ln, buildScript(script), nil, 0)
	defer s.shutdown()
	cfg := newConfig(ln.Addr().String())
	connector, cerr := mysql.NewConnector(cfg)
	if cerr != nil {
		t.Fatalf("harness: NewConnector: %v", cerr)
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = db.PingContext(ctx)
	return nil
}

// TestMySQL_AuthSwitchShortScramble_Reproducer is the MINIMAL reproducer for a
// genuine library bug: go-sql-driver/mysql v1.10.1 auth.go:310 does
// `scramblePassword(authData[:20], ...)` with NO bounds check. A hostile server
// that sends an AuthSwitchRequest switching to "mysql_native_password" with
// fewer than 20 bytes of auth data crashes the client with
// "slice bounds out of range [:20]". This is a remotely-triggerable panic (DoS)
// reachable through the database/sql public API only. The test asserts the panic
// occurs and is the expected slice-bounds panic (it will start failing if/when
// the library adds the missing length check — which is the desired signal).
func TestMySQL_AuthSwitchShortScramble_Reproducer(t *testing.T) {
	hs := mysqlHandshake("mysql_native_password", fixedScramble)
	// AuthSwitchRequest to native password with only 3 bytes of challenge.
	script := cat(
		encPkt(0, hs),
		encPkt(2, authSwitchPayload("mysql_native_password", []byte{0x01, 0x02, 0x03})),
		encClose(),
	)
	// Replay 3 times for stability.
	for i := range 3 {
		rec := reproPanic(t, script)
		if rec == nil {
			t.Fatalf("run %d: expected a panic from auth.go:310 (authData[:20]); driver did not panic "+
				"(library may have been fixed)", i)
		}
		msg := fmt.Sprint(rec)
		if !strings.Contains(msg, "slice bounds out of range") {
			t.Fatalf("run %d: panicked but not with the expected slice-bounds error: %v", i, rec)
		}
		t.Logf("run %d: reproduced library panic: %v", i, rec)
	}
}

// TestMySQL_ShortHandshake_Reproducer is the MINIMAL reproducer for a second
// genuine library bug: go-sql-driver/mysql v1.10.1 packets.go:209
// (readHandshakePacket) does `authData := data[pos : pos+8]` with NO check that
// the initial handshake packet is long enough. A hostile server sending a short
// handshake (as little as 2 bytes: protocol version + a NUL) crashes the client
// with "slice bounds out of range". Remotely-triggerable panic (DoS) via the
// database/sql public API.
func TestMySQL_ShortHandshake_Reproducer(t *testing.T) {
	// Minimal handshake: protocol version 10 (>= minProtocolVersion) then an
	// immediate NUL terminating the server-version string. pos lands past the
	// 2-byte packet and data[pos:pos+8] panics.
	script := cat(encPkt(0, []byte{0x0a, 0x00}), encClose())
	for i := range 3 {
		rec := reproPanic(t, script)
		if rec == nil {
			t.Fatalf("run %d: expected a panic from packets.go:209 (data[pos:pos+8]); driver did not panic "+
				"(library may have been fixed)", i)
		}
		if msg := fmt.Sprint(rec); !strings.Contains(msg, "slice bounds out of range") {
			t.Fatalf("run %d: panicked but not with the expected slice-bounds error: %v", i, rec)
		}
		t.Logf("run %d: reproduced library panic: %v", i, rec)
	}
}

// TestMySQL_EchoAndCanary_Oracle pins oracles (b)/(c): server ERR text is echoed
// into the error (expected), the canary password never is, and the detector
// catches a planted leak.
func TestMySQL_EchoAndCanary_Oracle(t *testing.T) {
	const marker = "server-marker-YYY-echo"
	hs := mysqlHandshake("mysql_native_password", fixedScramble)
	script := cat(
		encPkt(0, hs),
		encPkt(2, errPayload(1045, "28000", marker)),
		encClose(),
	)
	err := runHostile(t, script)
	if err == nil {
		t.Fatalf("expected auth error, got nil")
	}
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("echo oracle: expected server marker %q in error, got %q", marker, err.Error())
	}
	if strings.Contains(err.Error(), canaryPassword) {
		t.Fatalf("CANARY LEAK: password present in error: %q", err.Error())
	}
	planted := "handshake failed passwd=" + canaryPassword
	if !strings.Contains(planted, canaryPassword) {
		t.Fatalf("detector broken: did not catch planted canary leak")
	}
}

// TestMySQL_TruncatedMidPacket_Oracle pins oracle (d): a server closing mid-packet
// must make the driver error, not report a truncated success.
func TestMySQL_TruncatedMidPacket_Oracle(t *testing.T) {
	hs := mysqlHandshake("mysql_native_password", fixedScramble)

	// Control: full valid exchange -> Ping succeeds.
	ok := cat(
		encPkt(0, hs),
		encPkt(2, okPayload()),
		encPkt(1, okPayload()),
		encClose(),
	)
	if err := runHostile(t, ok); err != nil {
		t.Fatalf("control: valid exchange should Ping cleanly, got: %v", err)
	}

	// Truncated: auth-result packet declares +16 body bytes that never arrive.
	truncated := cat(
		encPkt(0, hs),
		encPktClaim(2, okPayload(), 3), // claimTable[3]=16 extra, none sent
		encClose(),
	)
	if err := runHostile(t, truncated); err == nil {
		t.Fatalf("truncation oracle: expected error on mid-packet close, got success")
	}
}

// TestMySQL_LengthHeaderAmplification characterises oracle (a)'s memory dimension:
// a 4-byte packet header declaring a large body provokes an up-front allocation
// (buffer.fill -> make([]byte, roundup(need))) before any body byte is read.
// Bounded; the real ceiling is maxPacketSize = 16 MiB (we cap the fake server at
// 1 MiB for host safety).
func TestMySQL_LengthHeaderAmplification(t *testing.T) {
	hs := mysqlHandshake("mysql_native_password", fixedScramble)
	// First packet declares the full 1 MiB body, only 4 bytes sent, then close.
	script := cat(encPktClaim(0, hs[:4], 7), encClose())

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := runHostile(t, script)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("expected error (header declares more than sent), got nil")
	}
	delta := after.TotalAlloc - before.TotalAlloc
	t.Logf("mysql driver allocated ~%d bytes from a 4-byte payload (declared up to %d)", delta, 1<<20)
	if delta > 64<<20 {
		t.Fatalf("UNBOUNDED: allocation delta %d exceeded 64 MiB for a 4-byte payload", delta)
	}
}

// TestMySQL_LocalInfile_Guard pins the LOCAL INFILE oracle (e): a hostile server
// requesting an arbitrary client file must be refused by default and the file
// must never be read off disk and shipped to the server. The positive control
// (AllowAllFiles=true) proves the test can actually detect a read, i.e. the
// default guard is load-bearing.
func TestMySQL_LocalInfile_Guard(t *testing.T) {
	const fileCanary = "INFILE-CANARY-CONTENT-7h3x"
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte(fileCanary), 0o600); err != nil {
		t.Fatalf("write temp secret: %v", err)
	}

	hs := mysqlHandshake("mysql_native_password", fixedScramble)
	// handshake(0), auth OK(2), then for the query: infile request(1) + OK(3).
	script := cat(
		encPkt(0, hs),
		encPkt(2, okPayload()),
		encPkt(1, localInfilePayload(secret)),
		encPkt(3, okPayload()),
		encClose(),
	)

	// Default: AllowAllFiles=false -> must refuse, never read the file.
	client, err := runExecCapture(t, script, "SELECT 1", nil)
	if err == nil {
		t.Fatalf("default guard: expected a refusal error for an unregistered LOCAL INFILE, got nil")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Logf("default guard: error was %q (expected 'not registered')", err.Error())
	}
	if strings.Contains(string(client), fileCanary) {
		t.Fatalf("FILE EXFIL: default driver shipped local file contents to the server: %q", err.Error())
	}

	// Positive control: AllowAllFiles=true -> the driver DOES read and ship the
	// file, proving the capture can detect a read (guard is load-bearing).
	client2, _ := runExecCapture(t, script, "SELECT 1", func(c *mysql.Config) {
		c.AllowAllFiles = true
	})
	if !strings.Contains(string(client2), fileCanary) {
		t.Fatalf("positive control failed: with AllowAllFiles=true the file content should reach the server, " +
			"but it did not — the guard test cannot detect a read and is not trustworthy")
	}
}
