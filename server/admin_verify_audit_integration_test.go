package main

// admin_verify_audit_integration_test.go exercises `keyorix-server admin
// verify-audit` (ADR-108 §B4, docs/design-b4-offline-audit-verify.md) as a
// real subprocess against the built binary — the same build-then-exec
// pattern admin_integration_test.go already uses for every other admin
// command, reusing its buildServerBinary/runAdmin/baseEnv/lockHolderHook
// helpers directly (same package, same file set).
//
// Scope: this file proves the COMMAND wires flags to internal/auditverify
// correctly, takes/skips the lock on the right path, and produces stable
// exit codes and JSON — not that the verification algorithm itself is
// correct (internal/auditverify's own test suite, particularly its
// differential tests against the real server writer, already proves that
// far more thoroughly). Fixtures here are built with direct SQL inserts
// using auditverify's own exported hash/sign helpers (ComputeEntryHash,
// SignCheckpoint) rather than driving a live server, which would need real
// authenticated traffic to generate audit events.

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	_ "modernc.org/sqlite"
)

// setupVerifyAuditDB runs init/diagnose/migrate against a fresh temp dir,
// returning the resulting config dir and the resolved SQLite file path.
func setupVerifyAuditDB(t *testing.T, bin string) (dir, dbPath string, env []string) {
	t.Helper()
	dir = t.TempDir()
	env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-verify-audit")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	return dir, filepath.Join(dir, "keyorix.db"), env
}

// seedAuditChain inserts n self-consistent chained audit_events rows
// directly via SQL, using auditverify.ComputeEntryHash so the chain is
// byte-identical to what the real writer would have produced. Continues
// from whatever chain already exists (init/diagnose/migrate each log a real
// admin.* event via recordAdminAction, so the table is never actually empty
// by the time a test calls this) rather than assuming genesis — restarting
// at genesis while real rows already exist would itself produce a broken
// prev_hash link, which is exactly the bug this comment exists to prevent
// reintroducing. Returns the certified (chainedEvents, headID, headHash) for
// the WHOLE chain, for a subsequent checkpoint.
func seedAuditChain(t *testing.T, dbPath string, n int) (chainedEvents int64, headID uint64, headHash string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer func() { _ = sqlDB.Close() }()

	var existingCount int64
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&existingCount); err != nil {
		t.Fatalf("count existing audit_events: %v", err)
	}
	prevHash := auditverify.GenesisHash
	if existingCount > 0 {
		if err := sqlDB.QueryRow("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&prevHash); err != nil {
			t.Fatalf("read existing chain head: %v", err)
		}
	}

	tr := true
	base := time.Now().UTC().Truncate(time.Second)
	for i := 1; i <= n; i++ {
		row := &auditverify.AuditEventRow{
			EventType:   "secret.read",
			IPAddress:   "10.0.0.1",
			Description: fmt.Sprintf("seeded event %d", i),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			ActorType:   "user",
		}
		entryHash := auditverify.ComputeEntryHash(row, prevHash)
		res, err := sqlDB.Exec(`INSERT INTO audit_events
			(event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			row.EventType, row.IPAddress, row.Description, tr, row.EventTime, "", false, row.ActorType, prevHash, entryHash)
		if err != nil {
			t.Fatalf("insert audit_events row %d: %v", i, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("LastInsertId: %v", err)
		}
		headID, headHash = uint64(id), entryHash
		prevHash = entryHash
	}
	return existingCount + int64(n), headID, headHash
}

// writeSignedCheckpoint inserts a correctly-signed audit_checkpoints row
// (using auditverify.SignCheckpoint, the same HMAC the real server computes)
// PLUS the paired audit_checkpoint_highwater system_metadata mark real
// checkpoint writes always advance together (internal/core's
// advanceAuditHighWater runs immediately after CreateAuditCheckpoint) — a
// checkpoint with no matching high-water mark is itself treated as tamper
// evidence by design (the mark being missing/malformed while a checkpoint
// exists is exactly what a deleted anti-rollback mark looks like), so a
// fixture that only wrote the checkpoint row would be testing that
// (different, also-real) failure mode instead of the truncation this helper
// exists to set up.
func writeSignedCheckpoint(t *testing.T, dbPath string, key []byte, chainedEvents int64, headID uint64, headHash string) {
	t.Helper()
	cp := &auditverify.Checkpoint{ChainedEvents: chainedEvents, HeadID: headID, HeadHash: headHash, KeyVersion: "v1"}
	sig := auditverify.SignCheckpoint(cp, key)

	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	defer func() { _ = sqlDB.Close() }()
	if _, err := sqlDB.Exec(`INSERT INTO audit_checkpoints
		(chained_events, head_id, head_hash, key_version, signature, created_at)
		VALUES (?,?,?,?,?,?)`,
		chainedEvents, headID, headHash, "v1", sig, time.Now().UTC()); err != nil {
		t.Fatalf("insert audit_checkpoints row: %v", err)
	}

	// High-water value layout mirrors internal/core.auditHighWaterValue:
	// "v1" \x1f chained_events \x1f head_id \x1f head_hash \x1f key_version \x1f sig
	// — the same fields, in the same order, joined with \x1f (not exported
	// by auditverify as a builder since only ParseHighWater is a public
	// contract; the format itself is documented in both packages' doc
	// comments and locked by auditverify's own
	// TestParseHighWater_RoundTrip).
	highWaterValue := strings.Join([]string{
		"v1",
		fmt.Sprintf("%d", chainedEvents),
		fmt.Sprintf("%d", headID),
		headHash,
		"v1",
		sig,
	}, "\x1f")
	if _, err := sqlDB.Exec(`INSERT INTO system_metadata (key, value, updated_at) VALUES (?,?,?)`,
		"audit_checkpoint_highwater", highWaterValue, time.Now().UTC()); err != nil {
		t.Fatalf("insert high-water mark: %v", err)
	}
}

func writeKeyFile(t *testing.T, dir string, key []byte) string {
	t.Helper()
	path := filepath.Join(dir, "checkpoint.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// verifyAuditExitCode runs verify-audit and returns (stdout+stderr, exit
// code). A process that never started (exec error) fails the test outright.
func verifyAuditExitCode(t *testing.T, bin, dir string, env []string, args ...string) (string, int) {
	t.Helper()
	out, err := runAdmin(t, bin, dir, env, append([]string{"verify-audit"}, args...)...)
	if err == nil {
		return out, 0
	}
	type exitCoder interface{ ExitCode() int }
	var ec exitCoder
	if ee, ok := err.(exitCoder); ok {
		ec = ee
	} else {
		t.Fatalf("verify-audit did not run (exec error, not a process exit): %v\n%s", err, out)
	}
	return out, ec.ExitCode()
}

func TestVerifyAudit_ValidChain_ExitZero_JSONSchemaStable(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	wantChained, wantHeadID, _ := seedAuditChain(t, dbPath, 10)

	out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml", "--json")
	if code != 0 {
		t.Fatalf("expected exit 0 for a clean chain, got %d:\n%s", code, out)
	}

	var result struct {
		Verdict       string `json:"verdict"`
		ChainedEvents int64  `json:"chained_events"`
		Range         struct {
			FromID uint64 `json:"from_id"`
			ToID   uint64 `json:"to_id"`
		} `json:"range"`
		Checkpoint struct {
			Present bool `json:"present"`
		} `json:"checkpoint"`
		RetentionGap struct {
			Present bool `json:"present"`
		} `json:"retention_gap"`
		NotProven       []string `json:"not_proven"`
		VerifierVersion string   `json:"verifier_version"`
	}
	// json output may be interleaved with informational log lines from
	// storage.OpenGormDB — isolate the JSON object itself.
	jsonStart := strings.Index(out, "{")
	if jsonStart < 0 {
		t.Fatalf("no JSON object found in output:\n%s", out)
	}
	if err := json.Unmarshal([]byte(out[jsonStart:]), &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v\n%s", err, out)
	}
	if result.Verdict != "VALID" {
		t.Errorf("expected verdict VALID, got %q", result.Verdict)
	}
	if result.ChainedEvents != wantChained {
		t.Errorf("expected %d chained events, got %d", wantChained, result.ChainedEvents)
	}
	if result.Range.FromID != 1 || result.Range.ToID != wantHeadID {
		t.Errorf("expected range 1..%d, got %d..%d", wantHeadID, result.Range.FromID, result.Range.ToID)
	}
	if result.Checkpoint.Present {
		t.Error("expected no checkpoint to be present")
	}
	if result.RetentionGap.Present {
		t.Error("expected no retention gap")
	}
	if len(result.NotProven) == 0 {
		t.Error("expected a non-empty not_proven section even on a clean VALID run")
	}
	if result.VerifierVersion == "" {
		t.Error("expected a non-empty verifier_version")
	}
}

func TestVerifyAudit_TamperedRow_ExitOne(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	_, headID, _ := seedAuditChain(t, dbPath, 5)

	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	// Tamper the fixture's own head row -- deterministic regardless of how
	// many admin.* events init/diagnose/migrate logged ahead of it.
	if _, err := sqlDB.Exec("UPDATE audit_events SET description = 'tampered' WHERE id = ?", headID); err != nil {
		t.Fatalf("tamper row: %v", err)
	}
	_ = sqlDB.Close()

	out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml")
	if code != 1 {
		t.Fatalf("expected exit 1 for a tampered chain, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Errorf("expected report to say BROKEN, got:\n%s", out)
	}
	wantLine := fmt.Sprintf("first broken id:  %d", headID)
	if !strings.Contains(out, wantLine) {
		t.Errorf("expected report to contain %q, got:\n%s", wantLine, out)
	}
}

func TestVerifyAudit_TruncatedTail_WithAndWithoutKey(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 10)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)
	keyFile := writeKeyFile(t, dir, key)

	sqlDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	// Drop the last 5 of THIS fixture's own 10 seeded rows, keeping whatever
	// admin.* events preceded it untouched.
	cutoff := headID - 5
	if _, err := sqlDB.Exec("DELETE FROM audit_events WHERE id > ?", cutoff); err != nil {
		t.Fatalf("truncate tail: %v", err)
	}
	_ = sqlDB.Close()

	t.Run("without key: bare re-walk cannot detect it", func(t *testing.T) {
		out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml")
		if code != 0 {
			t.Fatalf("expected exit 0 (ADR-029's documented bare-re-walk limit), got %d:\n%s", code, out)
		}
	})

	t.Run("with key: checkpoint enforcement catches it", func(t *testing.T) {
		out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml", "--checkpoint-key-file", keyFile)
		if code != 1 {
			t.Fatalf("expected exit 1 once the checkpoint key authenticates the certified length, got %d:\n%s", code, out)
		}
		// The anti-rollback high-water check runs before the checkpoint's own
		// length comparison (enforceCheckpoint's documented order), so either
		// message is a correct "checkpoint enforcement caught it" outcome.
		if !strings.Contains(out, "truncated below") {
			t.Errorf("expected a truncation-specific reason, got:\n%s", out)
		}
	})
}

func TestVerifyAudit_UsageError_ExitThree(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	out, code := verifyAuditExitCode(t, bin, dir, env, "--db", "/nonexistent/path/does-not-exist.db")
	if code != 3 {
		t.Fatalf("expected exit 3 for an unreadable --db path, got %d:\n%s", code, out)
	}
}

func TestVerifyAudit_LiveDBPath_TakesLock_CopyPathDoesNot(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	seedAuditChain(t, dbPath, 3)

	hook := startLockHolderHook(t, bin, dir, env)
	defer hook.release(t)

	t.Run("live-config path refuses while the exclusive lock is held", func(t *testing.T) {
		out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml")
		if code != 3 {
			t.Fatalf("expected exit 3 (usage/IO error: lock unavailable), got %d:\n%s", code, out)
		}
		if !strings.Contains(out, "another process holds this database") {
			t.Errorf("expected the specific lock-contention message, got:\n%s", out)
		}
	})

	t.Run("--db copy path succeeds regardless", func(t *testing.T) {
		out, code := verifyAuditExitCode(t, bin, dir, env, "--db", dbPath)
		if code != 0 {
			t.Fatalf("expected exit 0: an explicit --db copy must never be blocked by the live-DB lock, got %d:\n%s", code, out)
		}
	})
}
