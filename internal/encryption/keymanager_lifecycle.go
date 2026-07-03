// keymanager_lifecycle.go — KeyManager struct, constructor, and key initialisation.
//
// Handles first-boot key generation and subsequent startup unwrapping:
// NewKeyManager, Initialize, ensureSaltExists, ensureWrappedDEKExists, unwrapDEK.
//
// Primitive helpers (wrapKey, unwrapKey, wipeBytes) also live here — used by
// both lifecycle and rotation code.
//
// ADR-004 envelope encryption model:
//
//	Startup: passphrase → PBKDF2 → KEK (memory only)
//	         KEK unwraps wrapped DEK from disk → DEK (memory, process lifetime)
//	         KEK wiped from memory immediately after unwrap
//	On disk: keys/kek.salt (random salt, plaintext)
//	         keys/dek.key  (DEK wrapped with KEK, AES-256-GCM)
//	Never:   raw KEK on disk
//
// For rotation see keymanager_rotation.go. For get/validate/wipe see keymanager_io.go.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// KeyManager handles key lifecycle and storage.
type KeyManager struct {
	dekPath    string
	saltPath   string
	baseDir    string
	currentDEK []byte
	// dekSnapshot is the raw wrapped-DEK bytes read from disk at the moment
	// currentDEK was last set (Initialize/RotateDEKWithSweep/RotateDEK). It
	// lets RewrapDEK detect — under the exclusive key lock — whether another
	// process has changed dek.key since, so it never overwrites a
	// concurrently-completed rotation with a stale value (#195).
	dekSnapshot []byte
	keyVersion  string
	// keyProvider sources the KEK (ADR-038). nil = the legacy passphrase+salt
	// derivation below; set to a crypto.KeyProvider (password/file/env) by the
	// Service to obtain the KEK from elsewhere. Either way the KEK still wraps the
	// same on-disk DEK, so the data path is unchanged.
	keyProvider crypto.KeyProvider
	mu          sync.RWMutex
}

// SetKeyProvider configures where the KEK comes from. Must be called before
// Initialize / rotation. nil restores the legacy passphrase+salt derivation.
func (km *KeyManager) SetKeyProvider(p crypto.KeyProvider) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.keyProvider = p
}

// deriveKEK returns the KEK from the configured provider, or — when none is set —
// the legacy passphrase + on-disk salt PBKDF2 derivation (byte-identical to the
// pre-ADR-038 behaviour). The caller wipes the returned key.
func (km *KeyManager) deriveKEK(passphrase string) ([]byte, error) {
	if km.keyProvider != nil {
		return km.keyProvider.KEK()
	}
	if passphrase == "" {
		return nil, fmt.Errorf("master passphrase must not be empty")
	}
	salt, err := km.ensureSaltExists()
	if err != nil {
		return nil, fmt.Errorf("failed to ensure salt exists: %w", err)
	}
	return GenerateKEK(passphrase, salt, 600000), nil
}

// KeyInfo contains metadata about encryption keys.
type KeyInfo struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager(baseDir, dekPath, saltPath string) *KeyManager {
	return &KeyManager{
		dekPath:    dekPath,
		saltPath:   saltPath,
		baseDir:    baseDir,
		keyVersion: "v1",
	}
}

// Initialize sets up the key manager.
// First run: generates salt + DEK, wraps DEK with passphrase-derived KEK.
// Subsequent runs: loads salt, derives KEK, unwraps DEK, wipes KEK.
func (km *KeyManager) Initialize(passphrase string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	kek, err := km.deriveKEK(passphrase)
	if err != nil {
		return err
	}
	defer wipeBytes(kek)

	if err := km.ensureWrappedDEKExists(kek); err != nil {
		return fmt.Errorf("failed to ensure wrapped DEK exists: %w", err)
	}

	dek, err := km.unwrapDEK(kek)
	if err != nil {
		return fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	km.currentDEK = dek
	return nil
}

// ensureSaltExists returns the existing salt or generates a new one.
func (km *KeyManager) ensureSaltExists() ([]byte, error) {
	saltFullPath := filepath.Join(km.baseDir, km.saltPath)

	if _, err := os.Stat(saltFullPath); os.IsNotExist(err) {
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
		if err := securefiles.SecureWriteFileSync(km.baseDir, km.saltPath, salt, 0600); err != nil {
			return nil, fmt.Errorf("failed to write salt: %w", err)
		}
		fmt.Printf("✅ Generated new KEK salt at %s\n", saltFullPath)
		return salt, nil
	}

	salt, err := securefiles.SafeReadFile(km.baseDir, km.saltPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}
	if len(salt) != 32 {
		return nil, fmt.Errorf("invalid salt size: expected 32 bytes, got %d", len(salt))
	}
	return salt, nil
}

// ensureWrappedDEKExists generates and wraps a new DEK if none exists on disk.
func (km *KeyManager) ensureWrappedDEKExists(kek []byte) error {
	dekFullPath := filepath.Join(km.baseDir, km.dekPath)

	if _, err := os.Stat(dekFullPath); os.IsNotExist(err) {
		dek, err := GenerateRandomKey(32)
		if err != nil {
			return fmt.Errorf("failed to generate DEK: %w", err)
		}
		defer wipeBytes(dek)

		wrapped, err := wrapKey(dek, kek)
		if err != nil {
			return fmt.Errorf("failed to wrap DEK: %w", err)
		}
		if err := securefiles.SecureWriteFileSync(km.baseDir, km.dekPath, wrapped, 0600); err != nil {
			return fmt.Errorf("failed to write wrapped DEK: %w", err)
		}
		fmt.Printf("✅ Generated and wrapped new DEK at %s\n", dekFullPath)
	}

	return nil
}

// unwrapDEK reads the wrapped DEK from disk and decrypts it with the KEK.
func (km *KeyManager) unwrapDEK(kek []byte) ([]byte, error) {
	wrapped, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wrapped DEK: %w", err)
	}

	dek, err := unwrapKey(wrapped, kek)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK — wrong passphrase or corrupted key file: %w", err)
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("invalid DEK size after unwrap: expected 32 bytes, got %d", len(dek))
	}
	km.dekSnapshot = append([]byte(nil), wrapped...)
	return dek, nil
}

// wrapKey encrypts plainKey with kek using AES-256-GCM.
// Output: nonce (12 bytes) || ciphertext.
func wrapKey(plainKey, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plainKey, nil), nil
}

// unwrapKey decrypts a wrapped key using AES-256-GCM with kek.
func unwrapKey(wrapped, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short")
	}
	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	plainKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM open failed: %w", err)
	}
	return plainKey, nil
}

// wipeBytes overwrites a byte slice with zeros.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
