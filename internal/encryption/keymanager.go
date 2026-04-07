package encryption

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// KeyManager handles key lifecycle and storage
type KeyManager struct {
	kekPath    string
	dekPath    string
	baseDir    string
	currentKEK []byte
	currentDEK []byte
	keyVersion string
	mu         sync.RWMutex
}

// KeyInfo contains metadata about encryption keys
type KeyInfo struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
}

// NewKeyManager creates a new key manager
func NewKeyManager(baseDir, kekPath, dekPath string) *KeyManager {
	return &KeyManager{
		kekPath:    kekPath,
		dekPath:    dekPath,
		baseDir:    baseDir,
		keyVersion: "v1",
	}
}

// Initialize sets up the key manager and loads or generates keys
func (km *KeyManager) Initialize() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Ensure key files exist or create them
	if err := km.ensureKEKExists(); err != nil {
		return fmt.Errorf("failed to ensure KEK exists: %w", err)
	}

	if err := km.ensureDEKExists(); err != nil {
		return fmt.Errorf("failed to ensure DEK exists: %w", err)
	}

	// Load keys
	if err := km.loadKeys(); err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	return nil
}

// ensureKEKExists creates KEK file if it doesn't exist
func (km *KeyManager) ensureKEKExists() error {
	kekFullPath := filepath.Join(km.baseDir, km.kekPath)

	if _, err := os.Stat(kekFullPath); os.IsNotExist(err) {
		// Generate new KEK
		kek, err := GenerateRandomKey(32)
		if err != nil {
			return fmt.Errorf("failed to generate KEK: %w", err)
		}

		// Write KEK with secure permissions
		if err := securefiles.SecureWriteFile(km.baseDir, km.kekPath, kek, 0600); err != nil {
			return fmt.Errorf("failed to write KEK: %w", err)
		}

		fmt.Printf("✅ Generated new KEK at %s\n", kekFullPath)
	}

	return nil
}

// ensureDEKExists creates DEK file if it doesn't exist
func (km *KeyManager) ensureDEKExists() error {
	dekFullPath := filepath.Join(km.baseDir, km.dekPath)

	if _, err := os.Stat(dekFullPath); os.IsNotExist(err) {
		// Generate new DEK
		dek, err := GenerateRandomKey(32)
		if err != nil {
			return fmt.Errorf("failed to generate DEK: %w", err)
		}

		// Write DEK with secure permissions
		if err := securefiles.SecureWriteFile(km.baseDir, km.dekPath, dek, 0600); err != nil {
			return fmt.Errorf("failed to write DEK: %w", err)
		}

		fmt.Printf("✅ Generated new DEK at %s\n", dekFullPath)
	}

	return nil
}

// loadKeys loads KEK and DEK from files
func (km *KeyManager) loadKeys() error {
	// Load KEK
	kek, err := securefiles.SafeReadFile(km.baseDir, km.kekPath)
	if err != nil {
		return fmt.Errorf("failed to read KEK: %w", err)
	}
	if len(kek) != 32 {
		return fmt.Errorf("invalid KEK size: expected 32 bytes, got %d", len(kek))
	}
	km.currentKEK = kek

	// Load DEK
	dek, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return fmt.Errorf("failed to read DEK: %w", err)
	}
	if len(dek) != 32 {
		return fmt.Errorf("invalid DEK size: expected 32 bytes, got %d", len(dek))
	}
	km.currentDEK = dek

	return nil
}

// GetKEK returns the current KEK (thread-safe)
func (km *KeyManager) GetKEK() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Return a copy to prevent modification
	kek := make([]byte, len(km.currentKEK))
	copy(kek, km.currentKEK)
	return kek
}

// GetDEK returns the current DEK (thread-safe)
func (km *KeyManager) GetDEK() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Return a copy to prevent modification
	dek := make([]byte, len(km.currentDEK))
	copy(dek, km.currentDEK)
	return dek
}

// GetKeyVersion returns the current key version
func (km *KeyManager) GetKeyVersion() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyVersion
}

// RotateKEK generates a new KEK and updates the key version
func (km *KeyManager) RotateKEK() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Generate new KEK
	newKEK, err := GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate new KEK: %w", err)
	}

	// Backup old KEK
	oldKEKPath := fmt.Sprintf("%s.backup.%d", km.kekPath, time.Now().Unix())
	if err := securefiles.SecureWriteFile(km.baseDir, oldKEKPath, km.currentKEK, 0600); err != nil {
		return fmt.Errorf("failed to backup old KEK: %w", err)
	}

	// Write new KEK
	if err := securefiles.SecureWriteFile(km.baseDir, km.kekPath, newKEK, 0600); err != nil {
		return fmt.Errorf("failed to write new KEK: %w", err)
	}

	// Update in-memory KEK and version
	km.currentKEK = newKEK
	km.keyVersion = fmt.Sprintf("v%d", time.Now().Unix())

	fmt.Printf("✅ KEK rotated successfully. New version: %s\n", km.keyVersion)
	return nil
}

// RotateDEK generates a new DEK
func (km *KeyManager) RotateDEK() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Generate new DEK
	newDEK, err := GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate new DEK: %w", err)
	}

	// Backup old DEK
	oldDEKPath := fmt.Sprintf("%s.backup.%d", km.dekPath, time.Now().Unix())
	if err := securefiles.SecureWriteFile(km.baseDir, oldDEKPath, km.currentDEK, 0600); err != nil {
		return fmt.Errorf("failed to backup old DEK: %w", err)
	}

	// Write new DEK
	if err := securefiles.SecureWriteFile(km.baseDir, km.dekPath, newDEK, 0600); err != nil {
		return fmt.Errorf("failed to write new DEK: %w", err)
	}

	// Update in-memory DEK
	km.currentDEK = newDEK

	fmt.Printf("✅ DEK rotated successfully\n")
	return nil
}

// ValidateKeyFiles checks if key files exist and have correct permissions
func (km *KeyManager) ValidateKeyFiles() error {
	files := []securefiles.FilePermSpec{
		{Path: filepath.Join(km.baseDir, km.kekPath), Mode: 0600},
		{Path: filepath.Join(km.baseDir, km.dekPath), Mode: 0600},
	}

	return securefiles.FixFilePerms(files, false) // Check only, don't auto-fix
}

// FixKeyFilePermissions fixes key file permissions
func (km *KeyManager) FixKeyFilePermissions() error {
	files := []securefiles.FilePermSpec{
		{Path: filepath.Join(km.baseDir, km.kekPath), Mode: 0600},
		{Path: filepath.Join(km.baseDir, km.dekPath), Mode: 0600},
	}

	return securefiles.FixFilePerms(files, true) // Auto-fix permissions
}

// Wipe securely removes keys from memory
func (km *KeyManager) Wipe() {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Overwrite keys in memory with random data
	if km.currentKEK != nil {
		_, _ = rand.Read(km.currentKEK) // Explicitly ignore error for secure wipe
		km.currentKEK = nil
	}
	if km.currentDEK != nil {
		_, _ = rand.Read(km.currentDEK) // Explicitly ignore error for secure wipe
		km.currentDEK = nil
	}
}
