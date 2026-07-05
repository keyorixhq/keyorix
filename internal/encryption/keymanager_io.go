// keymanager_io.go — Key access, validation, and memory wipe.
//
// GetDEK, GetKeyVersion, GetEvidenceSignKey, ValidateKeyFiles, FixKeyFilePermissions, Wipe.
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

// GetEvidenceSignKey returns a copy of the KEK-derived evidence-signing key and its
// fingerprint ("key version"), or ok=false if the manager has not been initialized
// (no KEK has been derived yet, so no evidence-signing key exists).
func (km *KeyManager) GetEvidenceSignKey() (key []byte, keyID string, ok bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if len(km.evidenceSignKey) == 0 {
		return nil, "", false
	}
	key = make([]byte, len(km.evidenceSignKey))
	copy(key, km.evidenceSignKey)
	return key, km.evidenceSignKeyID, true
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

// Wipe securely removes the DEK and the evidence-signing key from memory.
func (km *KeyManager) Wipe() {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK != nil {
		wipeBytes(km.currentDEK)
		km.currentDEK = nil
	}
	if km.evidenceSignKey != nil {
		wipeBytes(km.evidenceSignKey)
		km.evidenceSignKey = nil
	}
}
