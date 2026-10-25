// review_encryptionops_auth_test.go — REVIEW-ENCRYPTIONOPS-1 findings on the
// auth-encryption commands.
//
// F1: with storage.encryption.enabled=false, AuthEncryption's encrypt/decrypt
// helpers pass bytes through unchanged. migrate then wrote the plaintext reset
// token into encrypted_token and reported "migrated to encrypted storage",
// validate decrypted that plaintext "successfully" and reported every check
// passed, and enable --force reported "enabled successfully" (and the admin tree
// audited it) while nothing was enabled.
//
// F2: every auth-encryption command discarded MasterPassphrase's error, so a
// refused or unreadable passphrase source (a too-open --passphrase-file, a bad
// --passphrase-fd) surfaced only as "master passphrase must not be empty".
package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAuthEncryptionCommands_EncryptionDisabled_RefuseWithoutTouchingRows(t *testing.T) {
	cases := []struct {
		name string
		// legacy seeds an unmigrated plaintext row. Off for validate: with one,
		// validate already fails (for the wrong reason), hiding the false pass.
		legacy bool
		run    func() error
	}{
		{"migrate", true, func() error { return MigrateAuthDataWithConfig(testConfig(false), false, zeroPassSrc()) }},
		{"validate", false, func() error { return ValidateAuthEncryptionWithConfig(testConfig(false), false, zeroPassSrc()) }},
		{"enable --force", true, func() error { return EnableAuthEncryptionWithConfig(testConfig(false), true, zeroPassSrc()) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)
			db := migrateEncOpsTables(t, testDBFile)
			legacy := models.PasswordReset{UserID: 7, Token: "plaintext-reset-token"}
			if tc.legacy {
				if err := db.Create(&legacy).Error; err != nil {
					t.Fatalf("create legacy row: %v", err)
				}
			}
			// A row whose "encrypted" column holds plaintext: what migrate wrote
			// under disabled encryption. validate must not call it decryptable.
			passthrough := models.PasswordReset{UserID: 8, EncryptedToken: []byte("not-a-ciphertext")}
			if err := db.Create(&passthrough).Error; err != nil {
				t.Fatalf("create passthrough row: %v", err)
			}
			if err := db.Exec("UPDATE password_resets SET token = NULL WHERE id = ?", passthrough.ID).Error; err != nil {
				t.Fatalf("null passthrough token: %v", err)
			}
			closeTestDB(db)

			out, err := captureOutput(t, tc.run)
			if err == nil {
				t.Fatalf("%s with storage.encryption.enabled=false returned success; output:\n%s", tc.name, out)
			}
			if !strings.Contains(err.Error(), "disabled") {
				t.Fatalf("%s: expected a disabled-encryption error, got: %v", tc.name, err)
			}
			if strings.Contains(out, "✅") {
				t.Fatalf("%s printed a success line although it refused:\n%s", tc.name, out)
			}

			if !tc.legacy {
				return
			}
			db2 := migrateEncOpsTables(t, testDBFile)
			defer closeTestDB(db2)
			var after models.PasswordReset
			if err := db2.First(&after, legacy.ID).Error; err != nil {
				t.Fatalf("read legacy row: %v", err)
			}
			if after.Token != "plaintext-reset-token" || len(after.EncryptedToken) != 0 {
				t.Fatalf("%s changed the legacy row under disabled encryption: token=%q encrypted_token=%q", tc.name, after.Token, after.EncryptedToken)
			}
		})
	}
}

func TestAuthEncryptionCommands_PassphraseSourceErrorIsReported(t *testing.T) {
	cmds := []struct {
		name string
		run  func(src crypto.PassphraseSource) error
	}{
		{"status", func(src crypto.PassphraseSource) error { return AuthStatusWithConfig(testConfig(true), src) }},
		{"enable", func(src crypto.PassphraseSource) error {
			return EnableAuthEncryptionWithConfig(testConfig(true), false, src)
		}},
		{"rotate", func(src crypto.PassphraseSource) error {
			return RotateAuthEncryptionWithConfig(testConfig(true), true, src)
		}},
		{"migrate", func(src crypto.PassphraseSource) error {
			return MigrateAuthDataWithConfig(testConfig(true), false, src)
		}},
		{"validate", func(src crypto.PassphraseSource) error {
			return ValidateAuthEncryptionWithConfig(testConfig(true), false, src)
		}},
	}
	for _, tc := range cmds {
		t.Run(tc.name, func(t *testing.T) {
			dir := chdirTemp(t)
			cfg := testConfig(true)
			setPassphraseEnv(t, testBaselinePassphrase)
			if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
			closeTestDB(migrateEncOpsTables(t, testDBFile))

			// The right passphrase, in a file the resolver refuses (group/world
			// readable). The command must say why, not "must not be empty".
			pf := filepath.Join(dir, "passphrase.txt")
			if err := os.WriteFile(pf, []byte(testBaselinePassphrase+"\n"), 0o600); err != nil {
				t.Fatalf("write passphrase file: %v", err)
			}
			if err := os.Chmod(pf, 0o644); err != nil {
				t.Fatalf("chmod passphrase file: %v", err)
			}
			src := crypto.PassphraseSource{FilePath: pf}
			_, wantErr := crypto.ResolvePassphrase(src, MasterPassphraseEnvVar)
			if wantErr == nil {
				t.Fatal("precondition: a 0644 --passphrase-file must be refused by ResolvePassphrase")
			}

			_, err := captureOutput(t, func() error { return tc.run(src) })
			if err == nil {
				t.Fatalf("%s accepted a refused passphrase source", tc.name)
			}
			if !strings.Contains(err.Error(), wantErr.Error()) {
				t.Fatalf("%s hid the passphrase-source error.\n got: %v\nwant it to contain: %v", tc.name, err, wantErr)
			}
		})
	}
}
