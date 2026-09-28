// recovery_key_encrypt_test.go — coverage for the age-encrypted recovery-key
// output path (F8): recipient parsing (both age1... and ssh-ed25519 file
// forms), the encrypt/decrypt round trip, and the output-file writer.
package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

// newTestSSHEd25519Recipient generates a real ssh-ed25519 key pair, returns
// its authorized_keys-format public line and the matching age.Identity
// (via agessh) that can decrypt what was encrypted to it.
func newTestSSHEd25519Recipient(t *testing.T) (authorizedKeyLine string, identity age.Identity) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	id, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatalf("build age identity from ssh key: %v", err)
	}
	return line, id
}

func decryptArmored(t *testing.T, armored []byte, identity age.Identity) string {
	t.Helper()
	r := armor.NewReader(bytes.NewReader(armored))
	dr, err := age.Decrypt(r, identity)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	out, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read decrypted plaintext: %v", err)
	}
	return string(out)
}

func TestParseRecoveryKeyRecipient_AgeString(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate x25519 identity: %v", err)
	}
	r, err := parseRecoveryKeyRecipient(id.Recipient().String())
	if err != nil {
		t.Fatalf("parseRecoveryKeyRecipient: %v", err)
	}

	encrypted, err := encryptRecoveryKeyForRecipient("test-raw-key-value", r)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got := decryptArmored(t, encrypted, id)
	if got != "test-raw-key-value" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestParseRecoveryKeyRecipient_SSHEd25519File(t *testing.T) {
	line, identity := newTestSSHEd25519Recipient(t)
	path := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write pub key file: %v", err)
	}

	r, err := parseRecoveryKeyRecipient(path)
	if err != nil {
		t.Fatalf("parseRecoveryKeyRecipient: %v", err)
	}

	encrypted, err := encryptRecoveryKeyForRecipient("another-raw-key", r)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got := decryptArmored(t, encrypted, identity)
	if got != "another-raw-key" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestParseRecoveryKeyRecipient_RejectsNonEd25519SSHKey(t *testing.T) {
	// A real RSA key pair — must be refused: only ssh-ed25519 is
	// documented/supported, even though agessh itself also supports ssh-rsa.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	path := filepath.Join(t.TempDir(), "id_rsa.pub")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write pub key file: %v", err)
	}
	_, perr := parseRecoveryKeyRecipient(path)
	if perr == nil {
		t.Fatal("expected an error for a non-ed25519 SSH key, got nil")
	}
	if !strings.Contains(perr.Error(), "ssh-ed25519") {
		t.Fatalf("expected the error to name ssh-ed25519, got: %v", perr)
	}
}

func TestParseRecoveryKeyRecipient_InvalidAgeString(t *testing.T) {
	_, err := parseRecoveryKeyRecipient("age1notavalidrecipient")
	if err == nil {
		t.Fatal("expected an error for an invalid age recipient, got nil")
	}
}

func TestParseRecoveryKeyRecipient_MissingFile(t *testing.T) {
	_, err := parseRecoveryKeyRecipient(filepath.Join(t.TempDir(), "does-not-exist.pub"))
	if err == nil {
		t.Fatal("expected an error for a missing recipient file, got nil")
	}
}

func TestWriteRecoveryKeyOutputFile_WritesWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.age")
	if err := writeRecoveryKeyOutputFile(path, []byte("ciphertext")); err != nil {
		t.Fatalf("writeRecoveryKeyOutputFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "ciphertext" {
		t.Fatalf("content mismatch: got %q", got)
	}
}

func TestWriteRecoveryKeyOutputFile_RefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.age")
	if err := os.WriteFile(path, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}
	err := writeRecoveryKeyOutputFile(path, []byte("new-content"))
	if err == nil {
		t.Fatal("expected an error when the output file already exists, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected an 'already exists' error, got: %v", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read back: %v", rerr)
	}
	if string(got) != "pre-existing" {
		t.Fatalf("existing file content was overwritten: got %q", got)
	}
}
