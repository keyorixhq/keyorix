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

// PBKDF2Iterations is the PBKDF2-SHA256 work factor and the SINGLE SOURCE OF TRUTH
// for the KEK-derivation iteration count across the codebase: encryption.DefaultKEKIterations
// is defined AS this constant, so the passphrase provider (which wrapped the on-disk DEK) and
// GenerateKEK / RotateKEKPassphrase (which must re-derive the SAME KEK to unwrap it) can never
// drift apart. Before this was unified they were two independent literals guarded asymmetrically
// (an exact value here, a floor `>= 600000` on the other), so raising one would have made
// rotate-kek derive a non-matching KEK (a fail-closed break — F-ENC-1, 2026-09-14 review).
// Changing this value orphans every existing wrapped DEK, so it must only ever change alongside
// a KEK re-wrap migration. 600000 matches OWASP's current PBKDF2-HMAC-SHA256 minimum.
const PBKDF2Iterations = 600000

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
	// iterations overrides PBKDF2Iterations when non-zero. Only ever set by
	// NewPasswordKeyProviderWithIterations, which only a _test.go file may call —
	// see that constructor's doc comment and
	// TestNewPasswordKeyProviderWithIterations_NoProductionCallers.
	iterations int
}

// NewPasswordKeyProvider builds the default passphrase-derived provider. saltPath
// is resolved under baseDir via the same securefiles guard as before.
func NewPasswordKeyProvider(passphrase, baseDir, saltPath string) *PasswordKeyProvider {
	return &PasswordKeyProvider{passphrase: passphrase, baseDir: baseDir, saltPath: saltPath}
}

// NewPasswordKeyProviderWithIterations is NewPasswordKeyProvider with an explicit
// PBKDF2 iteration-count override, for tests that want a cheap, throwaway KEK
// derivation instead of paying the real 600,000-iteration cost on every
// init/rotation — the dominant cost of internal/encryption's crash-consistency and
// fault-injection fuzz targets (each replays dozens of seeds, several of which
// re-derive the KEK). iterations != PBKDF2Iterations produces a KEK that cannot
// unwrap any real deployment's DEK, so this is a testing knob, not a config option:
// TestNewPasswordKeyProviderWithIterations_NoProductionCallers fails the build the
// moment any non-_test.go file anywhere in the repo calls this function.
func NewPasswordKeyProviderWithIterations(passphrase, baseDir, saltPath string, iterations int) *PasswordKeyProvider {
	return &PasswordKeyProvider{passphrase: passphrase, baseDir: baseDir, saltPath: saltPath, iterations: iterations}
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
	iterations := p.iterations
	if iterations == 0 {
		iterations = PBKDF2Iterations
	}
	return pbkdf2.Key([]byte(p.passphrase), salt, iterations, KEKSize, sha256.New), nil
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
		if err := securefiles.SecureWriteFileSync(p.baseDir, p.saltPath, salt, 0600); err != nil {
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
