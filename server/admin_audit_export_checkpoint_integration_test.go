package main

// admin_audit_export_checkpoint_integration_test.go exercises `keyorix-server
// admin audit export-checkpoint` (docs/design-b4-offline-audit-verify.md,
// the offline-anchor-source follow-up) as a real subprocess, reusing
// admin_verify_audit_integration_test.go's own fixture helpers
// (setupVerifyAuditDB/seedAuditChain/writeSignedCheckpoint/writeKeyFile/
// verifyAuditExitCode — same package, same file set) so the export command
// is tested against the exact same seeded-checkpoint shape that file's own
// verify-audit tests already trust.

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

func TestExportCheckpoint_HappyPath(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 10)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)

	outPath := filepath.Join(dir, "checkpoint-export.json")
	out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath)
	if err != nil {
		t.Fatalf("export-checkpoint failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Exported checkpoint") {
		t.Errorf("expected the export confirmation message, got:\n%s", out)
	}

	data, rerr := os.ReadFile(outPath)
	if rerr != nil {
		t.Fatalf("read exported file: %v", rerr)
	}
	bundle, perr := auditverify.ParseExternalAnchorBundle(data)
	if perr != nil {
		t.Fatalf("exported file did not parse as a valid anchor bundle: %v\n%s", perr, data)
	}
	if bundle.ChainedEvents != chainedEvents {
		t.Errorf("ChainedEvents = %d, want %d", bundle.ChainedEvents, chainedEvents)
	}
	if bundle.HeadID != headID {
		t.Errorf("HeadID = %d, want %d", bundle.HeadID, headID)
	}
	if bundle.HeadHash != headHash {
		t.Errorf("HeadHash = %q, want %q", bundle.HeadHash, headHash)
	}
	expectedSig := auditverify.SignCheckpoint(&auditverify.Checkpoint{
		ChainedEvents: chainedEvents, HeadID: headID, HeadHash: headHash, KeyVersion: "v1",
	}, key)
	if bundle.Signature != expectedSig {
		t.Errorf("exported Signature does not match what the checkpoint was actually signed with -- " +
			"export must copy the DB row's signature verbatim, never recompute it")
	}

	// The exported file must be immediately usable as --anchor, unmodified.
	verifyOut, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml",
		"--anchor", outPath, "--checkpoint-key-file", writeKeyFile(t, dir, key))
	if code != 0 {
		t.Fatalf("expected exit 0 verifying against the freshly exported anchor, got %d:\n%s", code, verifyOut)
	}
}

func TestExportCheckpoint_RefusesToOverwrite(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 5)
	key := []byte("0123456789abcdef0123456789abcdef")
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)

	outPath := filepath.Join(dir, "checkpoint-export.json")
	if out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath); err != nil {
		t.Fatalf("first export failed: %v\n%s", err, out)
	}

	out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath)
	if err == nil {
		t.Fatalf("expected the second export to refuse overwriting the existing file, got success:\n%s", out)
	}
	if !strings.Contains(out, "already exists") {
		t.Errorf("expected the specific already-exists message, got:\n%s", out)
	}
}

func TestExportCheckpoint_NoCheckpointYetRefuses(t *testing.T) {
	bin := buildServerBinary(t)
	dir, _, env := setupVerifyAuditDB(t, bin)
	// No seedAuditChain/writeSignedCheckpoint -- a fresh, just-migrated DB
	// has no audit_checkpoints row at all.

	outPath := filepath.Join(dir, "checkpoint-export.json")
	out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath)
	if err == nil {
		t.Fatalf("expected export-checkpoint to refuse when no checkpoint has ever been written, got success:\n%s", out)
	}
	if !strings.Contains(out, "no audit checkpoint has been written") {
		t.Errorf("expected the specific no-checkpoint message, got:\n%s", out)
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Errorf("expected no file to be created when the export itself failed")
	}
}

// TestExportCheckpoint_TamperedExportNotAuthenticated exercises the
// offline-anchor-source track's "tampered export rejected" requirement: a
// real export, subsequently tampered with (simulating an attacker
// intercepting the write-once media before it left the host, or a copy
// error), must never be silently trusted as authentic -- its HMAC signature
// no longer matches its (altered) content, so verify-audit must report it
// present-but-UNauthenticated and never use it for the chain-length
// cross-check, exactly like an anchor with no key at all.
func TestExportCheckpoint_TamperedExportNotAuthenticated(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 8)
	key := []byte("0123456789abcdef0123456789abcdef")
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)

	outPath := filepath.Join(dir, "checkpoint-export.json")
	if out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath); err != nil {
		t.Fatalf("export failed: %v\n%s", err, out)
	}

	// Tamper: claim MORE chained events than were actually certified, the
	// exact shape an attacker would want (inflate the certified length so a
	// REAL truncation looks covered by a bogus, inflated anchor).
	raw, rerr := os.ReadFile(outPath)
	if rerr != nil {
		t.Fatalf("read export: %v", rerr)
	}
	var bundle auditverify.ExternalAnchorBundle
	if jerr := json.Unmarshal(raw, &bundle); jerr != nil {
		t.Fatalf("unmarshal export: %v", jerr)
	}
	bundle.ChainedEvents += 1000
	tampered, merr := json.Marshal(&bundle)
	if merr != nil {
		t.Fatalf("marshal tampered bundle: %v", merr)
	}
	tamperedPath := filepath.Join(dir, "checkpoint-export-tampered.json")
	if werr := os.WriteFile(tamperedPath, tampered, 0600); werr != nil {
		t.Fatalf("write tampered export: %v", werr)
	}

	keyFile := writeKeyFile(t, dir, key)
	out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml",
		"--anchor", tamperedPath, "--checkpoint-key-file", keyFile, "--json")
	if code != 0 {
		t.Fatalf("expected exit 0 -- a tampered, UNauthenticated anchor must never gate the verdict "+
			"(the live chain itself was never touched), got %d:\n%s", code, out)
	}
	var result struct {
		ExternalAnchor struct {
			Supplied      bool `json:"supplied"`
			Authenticated bool `json:"authenticated"`
		} `json:"external_anchor"`
	}
	if jerr := json.Unmarshal([]byte(out), &result); jerr != nil {
		t.Fatalf("parse --json output: %v\n%s", jerr, out)
	}
	if !result.ExternalAnchor.Supplied {
		t.Errorf("expected external_anchor.supplied = true, got false")
	}
	if result.ExternalAnchor.Authenticated {
		t.Fatalf("expected the tampered export to be REJECTED as unauthenticated (signature no longer " +
			"matches the altered content), got authenticated = true")
	}
}

// TestExportCheckpoint_TruncationAfterExportDetected exercises the offline-
// anchor-source track's "truncation after export detected" requirement:
// export a genuine checkpoint (untouched, exactly as this command produced
// it), THEN truncate the live chain's tail below what that export
// certified (simulating a host-write attacker deleting rows after the
// export was taken and safely off-box), and confirm verify-audit catches
// it via the externally-held anchor -- the scenario this whole mechanism
// exists for (design §2's strongest leg: constrains even an admin who
// holds the checkpoint signing key, because the ground truth left the host
// before the tampering happened).
func TestExportCheckpoint_TruncationAfterExportDetected(t *testing.T) {
	bin := buildServerBinary(t)
	dir, dbPath, env := setupVerifyAuditDB(t, bin)
	chainedEvents, headID, headHash := seedAuditChain(t, dbPath, 10)
	key := []byte("0123456789abcdef0123456789abcdef")
	writeSignedCheckpoint(t, dbPath, key, chainedEvents, headID, headHash)

	outPath := filepath.Join(dir, "checkpoint-export.json")
	if out, err := runAdmin(t, bin, dir, env, "audit", "export-checkpoint", "--config", "./keyorix.yaml", "--output", outPath); err != nil {
		t.Fatalf("export failed: %v\n%s", err, out)
	}

	// Truncate the tail of THIS fixture's own 10 seeded rows (same
	// technique TestVerifyAudit_TruncatedTail_WithAndWithoutKey uses), AND
	// erase the LOCAL checkpoint/high-water record entirely -- simulating a
	// host-write attacker who deletes rows and forges/removes the local
	// certification too. This is the scenario design §2 says only an
	// externally-held anchor can catch: a bare re-walk, and even the
	// in-DB checkpoint/high-water mechanism, have nothing left locally to
	// compare against once both are gone -- ONLY the export this command
	// produced (already off the host before the tampering happened) still
	// knows the true prior length.
	sqlDB, serr := sql.Open("sqlite", dbPath)
	if serr != nil {
		t.Fatalf("open %s: %v", dbPath, serr)
	}
	cutoff := headID - 4
	if _, derr := sqlDB.Exec("DELETE FROM audit_events WHERE id > ?", cutoff); derr != nil {
		t.Fatalf("truncate tail: %v", derr)
	}
	if _, derr := sqlDB.Exec("DELETE FROM audit_checkpoints"); derr != nil {
		t.Fatalf("delete local checkpoint row: %v", derr)
	}
	if _, derr := sqlDB.Exec("DELETE FROM system_metadata WHERE key = ?", "audit_checkpoint_highwater"); derr != nil {
		t.Fatalf("delete local high-water mark: %v", derr)
	}
	_ = sqlDB.Close()

	keyFile := writeKeyFile(t, dir, key)

	// Confirms the premise: with BOTH local mechanisms gone, a bare re-walk
	// (even with the checkpoint key available) has nothing to compare
	// against and reports VALID -- the truncation is invisible without the
	// externally-held anchor.
	baseOut, baseCode := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml", "--checkpoint-key-file", keyFile)
	if baseCode != 0 {
		t.Fatalf("expected exit 0 with the local checkpoint/high-water record also erased (nothing left to "+
			"compare against locally) -- got %d, meaning some OTHER mechanism caught this and the anchor test "+
			"below wouldn't isolate what it claims to:\n%s", baseCode, baseOut)
	}

	out, code := verifyAuditExitCode(t, bin, dir, env, "--config", "./keyorix.yaml",
		"--anchor", outPath, "--checkpoint-key-file", keyFile)
	if code != 1 {
		t.Fatalf("expected exit 1 (BROKEN): the externally-held anchor certified %d events, only %d remain -- "+
			"got exit %d:\n%s", chainedEvents, chainedEvents-4, code, out)
	}
	if !strings.Contains(out, "truncated below an externally-held anchor") {
		t.Errorf("expected the specific externally-held-anchor truncation message, got:\n%s", out)
	}
}
