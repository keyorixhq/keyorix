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

// GetDEK returns a copy of the current DEK (thread-safe, lock-free).
func (km *KeyManager) GetDEK() []byte {
	st := km.state.Load()
	var src []byte
	if st != nil {
		src = st.currentDEK
	}
	dek := make([]byte, len(src))
	copy(dek, src)
	return dek
}

// GetKeyVersion returns the current key version string (lock-free).
func (km *KeyManager) GetKeyVersion() string {
	st := km.state.Load()
	if st == nil {
		return ""
	}
	return st.keyVersion
}

// GetEvidenceSignKey returns a copy of the KEK-derived evidence-signing key and its
// fingerprint ("key version"), or ok=false if the manager has not been initialized
// (no KEK has been derived yet, so no evidence-signing key exists). Lock-free.
func (km *KeyManager) GetEvidenceSignKey() (key []byte, keyID string, ok bool) {
	st := km.state.Load()
	if st == nil || len(st.evidenceSignKey) == 0 {
		return nil, "", false
	}
	key = make([]byte, len(st.evidenceSignKey))
	copy(key, st.evidenceSignKey)
	return key, st.evidenceSignKeyID, true
}

// GetAuditCheckpointKey returns a copy of the KEK-derived audit-checkpoint signing
// key and its fingerprint ("key version"), or ok=false if the manager has not been
// initialized (no KEK has been derived yet, so no checkpoint-signing key exists).
// Lock-free.
func (km *KeyManager) GetAuditCheckpointKey() (key []byte, keyID string, ok bool) {
	st := km.state.Load()
	if st == nil || len(st.auditCheckpointKey) == 0 {
		return nil, "", false
	}
	key = make([]byte, len(st.auditCheckpointKey))
	copy(key, st.auditCheckpointKey)
	return key, st.auditCheckpointKeyID, true
}

// GetBackupManifestKey returns a copy of the KEK-derived backup-manifest
// signing key and its fingerprint ("key version"), or ok=false if the
// manager has not been initialized -- design-b3-backup-v2.md §5.2/§5.3:
// both `admin backup` (to sign) and `admin restore` (to verify, after
// unwrapping the KEK from the archive's own staged key files) reach the
// key only through this getter, never the raw KEK itself. Lock-free.
func (km *KeyManager) GetBackupManifestKey() (key []byte, keyID string, ok bool) {
	st := km.state.Load()
	if st == nil || len(st.backupManifestKey) == 0 {
		return nil, "", false
	}
	key = make([]byte, len(st.backupManifestKey))
	copy(key, st.backupManifestKey)
	return key, st.backupManifestKeyID, true
}

// ValidateKeyFiles checks that key files exist and have correct permissions
// (0600). enc is the full encryption config (used to also cover any
// KeyProviderConfig-driven key material -- TPM/cloud-KMS wrapped-KEK blobs,
// Shamir share files -- via internal/keyfiles.Registry, not just the DEK and
// salt km itself was constructed with); nil checks DEK+salt only, for a
// KeyManager built without one (e.g. directly in a test).
func (km *KeyManager) ValidateKeyFiles(enc *config.EncryptionConfig) error {
	return km.checkKeyFilePerms(enc, km.baseDir, false)
}

// FixKeyFilePermissions corrects key file permissions to 0600. See
// ValidateKeyFiles for what enc adds.
func (km *KeyManager) FixKeyFilePermissions(enc *config.EncryptionConfig) error {
	return km.checkKeyFilePerms(enc, km.baseDir, true)
}

// checkKeyFilePerms audits (fix=false) or corrects (fix=true) the key files.
// registryBase is the base enc's other key paths resolve against: the Service's
// key base, which differs from km.baseDir when an absolute dek_path collapsed
// km.baseDir to the DEK's directory (#4504 F1).
func (km *KeyManager) checkKeyFilePerms(enc *config.EncryptionConfig, registryBase string, fix bool) error {
	files, err := km.keyFileSpecs(enc, registryBase)
	if err != nil {
		return err
	}
	return securefiles.FixFilePerms(files, fix)
}

// keyFileSpecs builds the FilePermSpec list shared by ValidateKeyFiles and
// FixKeyFilePermissions: km's own DEK/salt paths, plus (when enc is provided)
// every other key-material path internal/keyfiles.Registry derives from the
// full encryption config. km.dekPath/km.saltPath are used directly (rather
// than enc.DEKPath/enc.SaltPath) so this still works for a KeyManager built
// without a config at all.
func (km *KeyManager) keyFileSpecs(enc *config.EncryptionConfig, registryBase string) ([]securefiles.FilePermSpec, error) {
	dekFull := filepath.Join(km.baseDir, km.dekPath)
	files := []securefiles.FilePermSpec{{Path: dekFull, Mode: 0600}}
	seen := map[string]bool{dekFull: true}
	// No salt for a provider that does not read one (km.saltPath "", #4395):
	// joined anyway, the "salt" was the key directory itself and both audits
	// refused it as "not a regular file" (#4504 F3).
	if km.saltPath != "" {
		saltFull := filepath.Join(km.baseDir, km.saltPath)
		files = append(files, securefiles.FilePermSpec{Path: saltFull, Mode: 0600})
		seen[saltFull] = true
	}
	if enc == nil {
		return files, nil
	}
	specs, err := keyfiles.Registry(enc, registryBase)
	if err != nil {
		return nil, err
	}
	// enc's own SaltPath/DEKPath normally resolve to the same files as
	// km.dekPath/km.saltPath (both are set from the same config at
	// construction, see NewService) -- deduped here rather than trusted to
	// match, so a caller that ever passes a mismatched enc still gets km's
	// real DEK/salt checked exactly once, not silently dropped or doubled.
	for _, s := range specs {
		if seen[s.Path] {
			continue
		}
		seen[s.Path] = true
		files = append(files, s)
	}
	return files, nil
}

// Wipe securely removes the DEK, the evidence-signing key, the
// audit-checkpoint signing key, and the backup-manifest signing key from memory.
// Called only at process shutdown after all request handlers have returned.
func (km *KeyManager) Wipe() {
	km.rotateMu.Lock()
	defer km.rotateMu.Unlock()

	old := km.state.Load()
	if old == nil {
		return
	}
	// Publish a nil-key state before wiping so any reader loading after Store
	// sees empty keys rather than zeroed bytes still in flight.
	newState := &keyState{}
	newState.keyVersion = old.keyVersion
	km.state.Store(newState)

	// Wipe is called at shutdown after all handlers have returned, so no reader
	// holds the old pointer concurrently — safe to zero the bytes immediately.
	if old.currentDEK != nil {
		wipeBytes(old.currentDEK)
	}
	if old.evidenceSignKey != nil {
		wipeBytes(old.evidenceSignKey)
	}
	if old.auditCheckpointKey != nil {
		wipeBytes(old.auditCheckpointKey)
	}
	if old.backupManifestKey != nil {
		wipeBytes(old.backupManifestKey)
	}
}
