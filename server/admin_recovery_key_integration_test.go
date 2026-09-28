package main

// admin_recovery_key_integration_test.go exercises `keyorix-server admin
// recovery-key rotate` (docs/design-b2-recover-admin.md §2) as a real
// subprocess against the built binary, reusing this package's existing
// buildServerBinary/runAdmin/baseEnv/lockHolderHook harness
// (admin_integration_test.go).

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

var groupedRecoveryKeyForm = regexp.MustCompile(`[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){9}-[A-HJ-NP-Z2-9]{2}`)

func TestAdminRecoveryKey_GenerateThenRotate_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	// First run: no key exists yet — must report "generated", generation 1.
	firstOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("first recovery-key rotate failed: %v\n%s", err, firstOut)
	}
	if !strings.Contains(firstOut, "Recovery key generated (generation 1)") {
		t.Errorf("expected first run to report generation, got:\n%s", firstOut)
	}
	firstKey := groupedRecoveryKeyForm.FindString(firstOut)
	if firstKey == "" {
		t.Fatalf("expected a grouped recovery key in the output, got:\n%s", firstOut)
	}

	// Second run: a key already exists — must report "rotated", generation 2,
	// and print a DIFFERENT key than the first run.
	secondOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second recovery-key rotate failed: %v\n%s", err, secondOut)
	}
	if !strings.Contains(secondOut, "Recovery key rotated (generation 2)") {
		t.Errorf("expected second run to report rotation to generation 2, got:\n%s", secondOut)
	}
	secondKey := groupedRecoveryKeyForm.FindString(secondOut)
	if secondKey == "" {
		t.Fatalf("expected a grouped recovery key in the second run's output, got:\n%s", secondOut)
	}
	if secondKey == firstKey {
		t.Fatalf("expected rotation to produce a DIFFERENT key, got the same value twice: %q", firstKey)
	}

	// A third run must again report generation 3 — the counter keeps
	// advancing, not resetting or staying pinned at 2.
	thirdOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("third recovery-key rotate failed: %v\n%s", err, thirdOut)
	}
	if !strings.Contains(thirdOut, "Recovery key rotated (generation 3)") {
		t.Errorf("expected third run to report rotation to generation 3, got:\n%s", thirdOut)
	}
}

// TestAdminRecoveryKey_RotateWithRecipient_EncryptedOutputOnly is F8's own
// acceptance shape: `rotate --recipient <age1...> --output <file>` must
// write an age-armored ciphertext file (mode 0600) that decrypts back to
// the real recovery key, WITHOUT ever printing that key in plaintext to
// stdout -- the whole point of the flag.
func TestAdminRecoveryKey_RotateWithRecipient_EncryptedOutputOnly(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	outputPath := filepath.Join(dir, "recovery-key.age")

	out, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml",
		"--recipient", identity.Recipient().String(), "--output", outputPath)
	if err != nil {
		t.Fatalf("recovery-key rotate --recipient --output failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Recovery key generated (generation 1)") {
		t.Errorf("expected the generation line, got:\n%s", out)
	}
	if groupedRecoveryKeyForm.FindString(out) != "" {
		t.Fatalf("plaintext recovery key leaked to stdout despite --recipient:\n%s", out)
	}
	if strings.Contains(out, "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("armored ciphertext was printed to stdout even though --output was given:\n%s", out)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected output file mode 0600, got %v", info.Mode().Perm())
	}

	encrypted, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	ar := armor.NewReader(bytes.NewReader(encrypted))
	dr, err := age.Decrypt(ar, identity)
	if err != nil {
		t.Fatalf("age.Decrypt the output file: %v", err)
	}
	plaintext, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read decrypted plaintext: %v", err)
	}
	if !groupedRecoveryKeyForm.MatchString(string(plaintext)) {
		t.Fatalf("decrypted output file does not look like a recovery key: %q", plaintext)
	}

	// Re-running with the SAME --output path must refuse to overwrite.
	out2, err2 := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml",
		"--recipient", identity.Recipient().String(), "--output", outputPath)
	if err2 == nil {
		t.Fatalf("expected the second rotate with the same --output path to fail, got success:\n%s", out2)
	}
	if !strings.Contains(out2, "already exists") {
		t.Errorf("expected an 'already exists' refusal, got:\n%s", out2)
	}
}

// TestAdminRecoveryKey_OutputWithoutRecipient_Refused verifies --output
// alone (no --recipient) is refused outright -- this command must never
// write the PLAINTEXT key to a file.
func TestAdminRecoveryKey_OutputWithoutRecipient_Refused(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	out, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml",
		"--output", filepath.Join(dir, "should-not-be-created.age"))
	if err == nil {
		t.Fatalf("expected --output without --recipient to fail, got success:\n%s", out)
	}
	if !strings.Contains(out, "--output requires --recipient") {
		t.Errorf("expected the specific refusal message, got:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "should-not-be-created.age")); statErr == nil {
		t.Fatal("--output file was created despite the command failing")
	}
}

// TestAdminRecoveryKey_ConcurrentRotateRefusesWhileLockHeld exercises design
// §6's own adversarial-review checklist item: "Two concurrent recover-admin
// (or one recover-admin racing one rotate-key) invocations: the exclusive
// admin lock must serialize them; test the lock actually blocks a second
// acquirer rather than merely documenting that it should." Uses the same
// lockHolderHook subprocess harness TestAdminGuard_RefusesWhileServerRunning_
// ThenForceOverrides (admin_integration_test.go) uses to hold the exclusive
// lock deterministically, rather than racing two real commands' own
// (sub-second) work against each other.
func TestAdminRecoveryKey_ConcurrentRotateRefusesWhileLockHeld(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir)

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	holder := startLockHolderHook(t, bin, dir, env)
	released := false
	releaseOnce := func() {
		if released {
			return
		}
		released = true
		holder.release(t)
	}
	defer releaseOnce()

	out, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected recovery-key rotate to refuse while another admin command holds the exclusive lock, got success:\n%s", out)
	}
	if !strings.Contains(out, "admin commands must not run concurrently") {
		t.Errorf("expected the standard concurrent-admin-command refusal message, got:\n%s", out)
	}

	// Confirm the refusal actually prevented the write: release the lock and
	// rotate for real — this must be treated as the FIRST generation, not a
	// second one, proving the refused attempt above never touched storage.
	releaseOnce()
	realOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("recovery-key rotate after lock release failed: %v\n%s", err, realOut)
	}
	if !strings.Contains(realOut, "Recovery key generated (generation 1)") {
		t.Errorf("expected the refused attempt to have made no persisted change (still generation 1), got:\n%s", realOut)
	}
}

// TestAdminRecoveryKey_GenerateThenRotate_Postgres is the Postgres
// counterpart of TestAdminRecoveryKey_GenerateThenRotate_SQLite, per this
// repo's standing "SQLite + PG-gated" test convention (docs/security-
// closures.tsv's verification column). Gated on KEYORIX_TEST_PG_DSN; skips
// when unset.
func TestAdminRecoveryKey_GenerateThenRotate_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-recovery-key-pg")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: "8083"
  grpc:
    enabled: false
`, dsn)
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	firstOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("first recovery-key rotate failed: %v\n%s", err, firstOut)
	}
	if !strings.Contains(firstOut, "Recovery key generated (generation 1)") {
		t.Errorf("expected first run to report generation, got:\n%s", firstOut)
	}
	firstKey := groupedRecoveryKeyForm.FindString(firstOut)
	if firstKey == "" {
		t.Fatalf("expected a grouped recovery key in the output, got:\n%s", firstOut)
	}

	secondOut, err := runAdmin(t, bin, dir, env, "recovery-key", "rotate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second recovery-key rotate failed: %v\n%s", err, secondOut)
	}
	if !strings.Contains(secondOut, "Recovery key rotated (generation 2)") {
		t.Errorf("expected second run to report rotation to generation 2, got:\n%s", secondOut)
	}
	secondKey := groupedRecoveryKeyForm.FindString(secondOut)
	if secondKey == "" {
		t.Fatalf("expected a grouped recovery key in the second run's output, got:\n%s", secondOut)
	}
	if secondKey == firstKey {
		t.Fatalf("expected rotation to produce a DIFFERENT key, got the same value twice: %q", firstKey)
	}
}
