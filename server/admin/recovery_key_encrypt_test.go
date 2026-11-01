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

func TestReserveAndFinishRecoveryKeyOutputFile_WritesWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.age")
	f, err := reserveRecoveryKeyOutputFile(path)
	if err != nil {
		t.Fatalf("reserveRecoveryKeyOutputFile: %v", err)
	}
	if err := finishRecoveryKeyOutputFile(f, path, []byte("ciphertext")); err != nil {
		t.Fatalf("finishRecoveryKeyOutputFile: %v", err)
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

func TestReserveRecoveryKeyOutputFile_RefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.age")
	if err := os.WriteFile(path, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}
	_, err := reserveRecoveryKeyOutputFile(path)
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

// --- hybrid (post-quantum) recipients and the classical-recipient warning ---

func TestParseRecoveryKeyRecipient_HybridRoundTrip(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture's age.GenerateHybridIdentity (X25519 half) does not return under fips140=only (observed: 10-minute timeout). Production age recipients are refused there: open item 2 in docs/design/fips140-only-observations.md, shown by TestParseRecoveryKeyRecipient_AgeString failing")
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate hybrid identity: %v", err)
	}
	spec := id.Recipient().String()
	if !strings.HasPrefix(spec, "age1pq1") {
		t.Fatalf("test premise: hybrid recipient should start with age1pq1, got %.12s...", spec)
	}
	r, err := parseRecoveryKeyRecipient(spec)
	if err != nil {
		t.Fatalf("parseRecoveryKeyRecipient(hybrid): %v", err)
	}
	encrypted, err := encryptRecoveryKeyForRecipient("hybrid-raw-key", r)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got := decryptArmored(t, encrypted, id); got != "hybrid-raw-key" {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

func TestParseRecoveryKeyRecipient_MalformedHybridRefused(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture's age.GenerateHybridIdentity (X25519 half) does not return under fips140=only (observed: 10-minute timeout). Production age recipients are refused there: open item 2 in docs/design/fips140-only-observations.md, shown by TestParseRecoveryKeyRecipient_AgeString failing")
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate hybrid identity: %v", err)
	}
	valid := id.Recipient().String()
	for name, spec := range map[string]string{
		"garbage":   "age1pq1notavalidrecipient",
		"truncated": valid[:len(valid)-8],
	} {
		t.Run(name, func(t *testing.T) {
			r, perr := parseRecoveryKeyRecipient(spec)
			if perr == nil || r != nil {
				t.Fatalf("expected a refusal for %q, got recipient=%v err=%v", name, r, perr)
			}
			if !strings.Contains(perr.Error(), "hybrid") {
				t.Fatalf("error should say it was parsed as a hybrid recipient, got: %v", perr)
			}
		})
	}
}

func TestWarnIfClassicalRecoveryKeyRecipient(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture's age.GenerateHybridIdentity (X25519 half) does not return under fips140=only (observed: 10-minute timeout). Production age recipients are refused there: open item 2 in docs/design/fips140-only-observations.md, shown by TestParseRecoveryKeyRecipient_AgeString failing")
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate hybrid identity: %v", err)
	}
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate x25519 identity: %v", err)
	}
	line, _ := newTestSSHEd25519Recipient(t)
	sshPath := filepath.Join(t.TempDir(), "id_ed25519.pub")
	if err := os.WriteFile(sshPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write pub key file: %v", err)
	}

	cases := []struct {
		name     string
		spec     string
		wantWarn bool
	}{
		{"hybrid", hybrid.Recipient().String(), false},
		{"x25519", x25519.Recipient().String(), true},
		{"ssh-ed25519", sshPath, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseRecoveryKeyRecipient(tc.spec)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var buf bytes.Buffer
			warnIfClassicalRecoveryKeyRecipient(&buf, r)
			out := buf.String()
			if !tc.wantWarn {
				if out != "" {
					t.Fatalf("hybrid recipient must not warn, got: %q", out)
				}
				return
			}
			if n := strings.Count(out, "WARNING"); n != 1 {
				t.Fatalf("expected exactly one warning, got %d: %q", n, out)
			}
			for _, want := range []string{"quantum", "age1pq"} {
				if !strings.Contains(out, want) {
					t.Fatalf("warning should mention %q, got: %q", want, out)
				}
			}
			// No key material: neither the recipient string nor the key file's content.
			if strings.Contains(out, tc.spec) || strings.Contains(out, line) {
				t.Fatalf("warning leaked recipient material: %q", out)
			}
		})
	}
}
