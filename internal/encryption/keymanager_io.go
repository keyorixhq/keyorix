// keymanager_io.go — Key access, validation, and memory wipe.
//
// GetDEK, GetKeyVersion, ValidateKeyFiles, FixKeyFilePermissions, Wipe.
// For initialisation see keymanager_lifecycle.go. For rotation see keymanager_rotation.go.
package encryption

import (
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// GetDEK returns a copy of the current DEK (thread-safe).
func (km *KeyManager) GetDEK() []byte {
	km.mu.RLock()
	defer km.mu.RUnlock()

	dek := make([]byte, len(km.currentDEK))
	copy(dek, km.currentDEK)
	return dek
}

// GetKeyVersion returns the current key version string.
func (km *KeyManager) GetKeyVersion() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyVersion
}

// ValidateKeyFiles checks that key files exist and have correct permissions (0600).
func (km *KeyManager) ValidateKeyFiles() error {
	files := []securefiles.FilePermSpec{
		{Path: filepath.Join(km.baseDir, km.dekPath), Mode: 0600},
		{Path: filepath.Join(km.baseDir, km.saltPath), Mode: 0600},
	}
	return securefiles.FixFilePerms(files, false)
}

// FixKeyFilePermissions corrects key file permissions to 0600.
func (km *KeyManager) FixKeyFilePermissions() error {
	files := []securefiles.FilePermSpec{
		{Path: filepath.Join(km.baseDir, km.dekPath), Mode: 0600},
		{Path: filepath.Join(km.baseDir, km.saltPath), Mode: 0600},
	}
	return securefiles.FixFilePerms(files, true)
}

// Wipe securely removes the DEK from memory.
func (km *KeyManager) Wipe() {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK != nil {
		wipeBytes(km.currentDEK)
		km.currentDEK = nil
	}
}
