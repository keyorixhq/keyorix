package main

// sqlite_rotation_protocol_integration_test.go -- KEY-ROTATION-TAILS-NOV-1
// item 3. On PostgreSQL every server start records dek.rotation_protocol
// (StartDEKEpochGuard); on SQLite only a rotation did, so a SQLite data dir a
// newer server had served but never rotated carried no marker, and a later
// SQLite-relevant protocol bump could not stop an older admin binary there.
//
// The real server binary starts on a SQLite data dir and must leave the
// marker. An admin binary one protocol older than that server is simulated by
// raising the recorded value by one (the comparison is recorded > own, so
// "server N+1, admin N" and "server N, admin N-1" are the same check); `admin
// encryption rotate` and `admin restore` must then refuse and change nothing.

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const rotationProtocolKey = "dek.rotation_protocol"

func readRotationProtocol(t *testing.T, dbPath string) (string, bool) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open %s read-only: %v", dbPath, err)
	}
	defer db.Close() //nolint:errcheck
	var v string
	switch err := db.QueryRow("SELECT value FROM system_metadata WHERE key = ?", rotationProtocolKey).Scan(&v); {
	case err == sql.ErrNoRows:
		return "", false
	case err != nil:
		t.Fatalf("read %s: %v", rotationProtocolKey, err)
	}
	return v, true
}

func TestSQLiteServerStart_RecordsRotationProtocol_OlderAdminRefusesRotateAndRestore(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-rotation-protocol")
	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	pinFreeHTTPPort(t, dir)
	adminEncryptionInit(t, bin, dir, env)
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "backup", "--config", "./keyorix.yaml", "--output", "./backup.tar.gz"); err != nil {
		t.Fatalf("admin backup failed: %v\n%s", err, out)
	}
	dbPath := filepath.Join(dir, "keyorix.db")
	if v, found := readRotationProtocol(t, dbPath); found {
		t.Fatalf("fixture: %s is already %q before any server start; the test would prove nothing", rotationProtocolKey, v)
	}

	// Start the real server and wait until it has recorded the marker.
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), env...), "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close() //nolint:errcheck
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop := func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	t.Cleanup(stop)
	recorded, found := "", false
	ready := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && !found; {
		select {
		case <-exited:
			deadline = time.Now()
		default:
		}
		if recorded, found = readRotationProtocol(t, dbPath); !found {
			b, _ := os.ReadFile(logPath) // #nosec G304 -- the test's own log
			ready = strings.Contains(string(b), "Encryption initialised")
			if ready {
				// Startup has passed the encryption step; one more read settles it.
				recorded, found = readRotationProtocol(t, dbPath)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	stop()
	if !found {
		b, _ := os.ReadFile(logPath) // #nosec G304 -- the test's own log
		t.Errorf("a SQLite data dir started by the server has no %s (encryption startup reached: %v); server log:\n%s", rotationProtocolKey, ready, b)
		// Go on with the protocol that introduced the marker, so the refusals
		// below are checked as well.
		recorded = "2"
	}
	own, err := strconv.Atoi(recorded)
	if err != nil || own < 2 {
		t.Fatalf("recorded %s = %q, want an integer >= 2", rotationProtocolKey, recorded)
	}

	// The server is one protocol newer than this admin binary from now on.
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO system_metadata (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, rotationProtocolKey, strconv.Itoa(own+1)); err != nil {
		t.Fatalf("raise %s: %v", rotationProtocolKey, err)
	}
	_ = db.Close()
	dekPath := filepath.Join(dir, "keys", "dek.key")
	dekBefore, err := os.ReadFile(dekPath) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	dbBefore, err := os.ReadFile(dbPath) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}

	out, err := runAdmin(t, bin, dir, env, "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "rotation protocol") {
		t.Errorf("admin encryption rotate by an admin binary older than the server's rotation protocol: err=%v, want a refusal naming the rotation protocol; output:\n%s", err, out)
	}
	out, err = runAdmin(t, bin, dir, env, "restore", "--config", "./keyorix.yaml", "--input", "./backup.tar.gz",
		"--overwrite-existing", "--replace-existing-data", "--allow-rollback")
	if err == nil || !strings.Contains(out, "rotation protocol") {
		t.Errorf("admin restore by an admin binary older than the server's rotation protocol: err=%v, want a refusal naming the rotation protocol; output:\n%s", err, out)
	}
	if b, _ := os.ReadFile(dekPath); string(b) != string(dekBefore) { // #nosec G304 -- test fixture
		t.Error("a refused command changed dek.key")
	}
	if b, _ := os.ReadFile(dbPath); string(b) != string(dbBefore) { // #nosec G304 -- test fixture
		t.Error("a refused command changed the database file")
	}
	if v, _ := readRotationProtocol(t, dbPath); v != strconv.Itoa(own+1) {
		t.Errorf("%s = %q after the refusals, want %d (never lowered)", rotationProtocolKey, v, own+1)
	}
}
