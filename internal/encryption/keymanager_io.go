// keymanager_io.go — Key access, validation, and memory wipe.
//
// GetDEK, GetKeyVersion, GetEvidenceSignKey, ValidateKeyFiles, FixKeyFilePermissions, Wipe.
// For initialisation see keymanager_lifecycle.go. For rotation see keymanager_rotation.go.
package encryption

import (
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
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

// GetAuditCheckpointKey returns a copy of the KEK-derived audit-checkpoint signing
// key and its fingerprint ("key version"), or ok=false if the manager has not been
// initialized (no KEK has been derived yet, so no checkpoint-signing key exists).
func (km *KeyManager) GetAuditCheckpointKey() (key []byte, keyID string, ok bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if len(km.auditCheckpointKey) == 0 {
		return nil, "", false
	}
	key = make([]byte, len(km.auditCheckpointKey))
	copy(key, km.auditCheckpointKey)
	return key, km.auditCheckpointKeyID, true
}

// ValidateKeyFiles checks that key files exist and have correct permissions
// (0600). enc is the full encryption config (used to also cover any
// KeyProviderConfig-driven key material -- TPM/cloud-KMS wrapped-KEK blobs,
// Shamir share files -- via internal/keyfiles.Registry, not just the DEK and
// salt km itself was constructed with); nil checks DEK+salt only, for a
// KeyManager built without one (e.g. directly in a test).
func (km *KeyManager) ValidateKeyFiles(enc *config.EncryptionConfig) error {
	files, err := km.keyFileSpecs(enc)
	if err != nil {
		return err
	}
	return securefiles.FixFilePerms(files, false)
}

// FixKeyFilePermissions corrects key file permissions to 0600. See
// ValidateKeyFiles for what enc adds.
func (km *KeyManager) FixKeyFilePermissions(enc *config.EncryptionConfig) error {
	files, err := km.keyFileSpecs(enc)
	if err != nil {
		return err
	}
	return securefiles.FixFilePerms(files, true)
}

// keyFileSpecs builds the FilePermSpec list shared by ValidateKeyFiles and
// FixKeyFilePermissions: km's own DEK/salt paths, plus (when enc is provided)
// every other key-material path internal/keyfiles.Registry derives from the
// full encryption config. km.dekPath/km.saltPath are used directly (rather
// than enc.DEKPath/enc.SaltPath) so this still works for a KeyManager built
// without a config at all.
func (km *KeyManager) keyFileSpecs(enc *config.EncryptionConfig) ([]securefiles.FilePermSpec, error) {
	dekFull := filepath.Join(km.baseDir, km.dekPath)
	saltFull := filepath.Join(km.baseDir, km.saltPath)
	files := []securefiles.FilePermSpec{
		{Path: dekFull, Mode: 0600},
		{Path: saltFull, Mode: 0600},
	}
	if enc == nil {
		return files, nil
	}
	specs, err := keyfiles.Registry(enc, km.baseDir)
	if err != nil {
		return nil, err
	}
	// enc's own SaltPath/DEKPath normally resolve to the same files as
	// km.dekPath/km.saltPath (both are set from the same config at
	// construction, see NewService) -- deduped here rather than trusted to
	// match, so a caller that ever passes a mismatched enc still gets km's
	// real DEK/salt checked exactly once, not silently dropped or doubled.
	seen := map[string]bool{dekFull: true, saltFull: true}
	for _, s := range specs {
		if seen[s.Path] {
			continue
		}
		seen[s.Path] = true
		files = append(files, s)
	}
	return files, nil
}

// Wipe securely removes the DEK, the evidence-signing key, and the
// audit-checkpoint signing key from memory.
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
	if km.auditCheckpointKey != nil {
		wipeBytes(km.auditCheckpointKey)
		km.auditCheckpointKey = nil
	}
}
