// review_encryptionops_shamir_test.go — REVIEW-ENCRYPTIONOPS-1 F5.
//
// migrate-provider --to-type shamir accepted share files without a KEK
// commitment. Shamir interpolation is linear, so whoever holds threshold-1
// genuine shares can forge one more share that makes the reconstructed KEK any
// value they choose, framing magic included (#429). migrate-provider then
// wrapped the live DEK under that attacker-known KEK and reported success; only
// a log line warned. The commitment shamir-split prints is the check that
// catches it, and a migration is a new binding with no pre-#429 split to keep
// working, so the commitment is required here.
package encryptionops

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// gf256Mul and gf256Inv are GF(2^8) arithmetic over the Rijndael polynomial,
// the field internal/crypto's Shamir split uses; the forger needs no more.
func gf256Mul(a, b byte) byte {
	var p byte
	for range 8 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func gf256Inv(a byte) byte {
	r := byte(1)
	for range 254 {
		r = gf256Mul(r, a)
	}
	return r
}

// forgeSecondShare returns a share with x-coordinate x2 such that combining it
// with the genuine share (threshold 2) reconstructs magic ‖ 2 ‖ kek.
func forgeSecondShare(genuine []byte, x2 byte, kek []byte) []byte {
	x1 := genuine[len(genuine)-1]
	payload := append([]byte("KXK1"), 2)
	payload = append(payload, kek...)
	forged := make([]byte, len(genuine))
	for i, s := range payload {
		slope := gf256Mul(genuine[i]^s, gf256Inv(x1))
		forged[i] = s ^ gf256Mul(slope, x2)
	}
	forged[len(forged)-1] = x2
	return forged
}

func TestMigrateProviderWithConfig_Shamir_ForgedShareWithoutCommitmentRefused(t *testing.T) {
	dir := chdirTemp(t)
	cfg, _ := migrateFixture(t)
	before, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}

	realKEK := bytes.Repeat([]byte{0xA5}, crypto.KEKSize)
	realKEK[0] = 0x01
	shares, err := crypto.SplitKEK(realKEK, 3, 2)
	if err != nil {
		t.Fatalf("SplitKEK: %v", err)
	}
	attackerKEK := bytes.Repeat([]byte{0x3C}, crypto.KEKSize)
	attackerKEK[0] = 0x02
	forged := forgeSecondShare(shares[0], 2, attackerKEK)

	f1 := filepath.Join(dir, "share-1.hex")
	f2 := filepath.Join(dir, "share-2.hex")
	if err := os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte(hex.EncodeToString(forged)), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := captureOutput(t, func() error {
		return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "shamir", ToShareFiles: []string{f1, f2}}, true, zeroPassSrc(), zeroPassSrc())
	})
	if err == nil {
		t.Fatalf("migrate-provider wrapped the DEK under a KEK reconstructed from a forged share (attacker-chosen KEK %x); output:\n%s", attackerKEK, out)
	}
	if !strings.Contains(err.Error(), "--to-shamir-commitment") {
		t.Fatalf("expected a refusal naming --to-shamir-commitment, got: %v", err)
	}
	after, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dek.key changed although the migration was refused")
	}
	if backups, _ := FindMigrateBackups(".", cfg.Storage.Encryption.DEKPath); len(backups) != 0 {
		t.Fatalf("a refused migration left backups: %v", backups)
	}
}

func TestTargetEncryptionConfig_Shamir_CommitmentMustBe32HexBytes(t *testing.T) {
	good := hex.EncodeToString(crypto.CommitKEK(bytes.Repeat([]byte{7}, crypto.KEKSize)))
	for _, tc := range []struct {
		name, commitment string
		ok               bool
	}{
		{"missing", "", false},
		{"whitespace", "   ", false},
		{"not hex", strings.Repeat("zz", 32), false},
		{"too short", good[:32], false},
		{"valid", good, true},
		{"valid with newline", good + "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "shamir", ToShareFiles: []string{"a", "b"}, ToShareCommitment: tc.commitment})
			if tc.ok {
				if err != nil {
					t.Fatalf("valid commitment refused: %v", err)
				}
				if tgt.KeyProvider.ShamirCommitment != good {
					t.Fatalf("commitment not normalised: %q", tgt.KeyProvider.ShamirCommitment)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "--to-shamir-commitment") {
				t.Fatalf("commitment %q: expected a refusal naming --to-shamir-commitment, got %v", tc.commitment, err)
			}
		})
	}
}
