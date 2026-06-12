package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2Iterations is the PBKDF2-SHA256 work factor. This value MUST match the
// historical KEK derivation (encryption.GenerateKEK used 600000) so an existing
// wrapped DEK still unwraps — changing it would orphan all encrypted data.
const pbkdf2Iterations = 600000

// saltSize is the KEK-salt length in bytes (must match the historical 32).
const saltSize = 32

// PasswordKeyProvider derives the KEK from a passphrase via PBKDF2-SHA256 over a
// random, on-disk salt — the original (ADR-004) behaviour, now behind the
// KeyProvider interface. Byte-for-byte compatible with the legacy derivation:
// same salt file, same iteration count, same KDF, so existing deployments are
// unaffected.
type PasswordKeyProvider struct {
	passphrase string
	baseDir    string
	saltPath   string
}

// NewPasswordKeyProvider builds the default passphrase-derived provider. saltPath
// is resolved under baseDir via the same securefiles guard as before.
func NewPasswordKeyProvider(passphrase, baseDir, saltPath string) *PasswordKeyProvider {
	return &PasswordKeyProvider{passphrase: passphrase, baseDir: baseDir, saltPath: saltPath}
}

func (p *PasswordKeyProvider) Name() string { return "password" }

// KEK ensures the salt exists (generating it on first run) and derives the KEK.
func (p *PasswordKeyProvider) KEK() ([]byte, error) {
	if p.passphrase == "" {
		return nil, fmt.Errorf("password key provider: master passphrase must not be empty")
	}
	salt, err := p.ensureSalt()
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key([]byte(p.passphrase), salt, pbkdf2Iterations, KEKSize, sha256.New), nil
}

// ensureSalt mirrors the historical KeyManager.ensureSaltExists exactly: read the
// 32-byte salt if present, otherwise generate one and persist it 0600.
func (p *PasswordKeyProvider) ensureSalt() ([]byte, error) {
	full := filepath.Join(p.baseDir, p.saltPath)
	if _, err := os.Stat(full); os.IsNotExist(err) {
		salt := make([]byte, saltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		if err := securefiles.SecureWriteFile(p.baseDir, p.saltPath, salt, 0600); err != nil {
			return nil, fmt.Errorf("failed to write salt: %w", err)
		}
		return salt, nil
	}
	salt, err := securefiles.SafeReadFile(p.baseDir, p.saltPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", saltSize, len(salt))
	}
	return salt, nil
}
