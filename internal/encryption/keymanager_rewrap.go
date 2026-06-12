// keymanager_rewrap.go — KEK-provider migration: re-wrap the DEK under a new KEK
// without re-encrypting any data (ADR-041).
//
// Unlike RotateDEKWithSweep (which generates a NEW DEK and re-encrypts every row),
// RewrapDEK keeps the SAME DEK and only changes the key that wraps it on disk. The
// data path is untouched, so this is fast and holds no database lock — it is how an
// existing install moves between KEK providers (e.g. password → cloud KMS).
package encryption

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// RewrapDEK re-wraps the in-memory DEK with a KEK sourced from newProvider and
// atomically replaces the on-disk wrapped DEK (write-pending-then-rename). The DEK
// value is unchanged, so all existing ciphertext stays valid — only the wrapping
// key changes. The manager must already be Initialized (DEK in memory) with the
// CURRENT provider.
//
// newProvider.KEK() persists the new provider's own key material as a side effect
// (a fresh salt for password, a KMS-wrapped KEK blob for the kms providers); this
// happens before the DEK file is touched, so a failure here leaves the active DEK
// untouched and the old provider still working.
func (km *KeyManager) RewrapDEK(newProvider crypto.KeyProvider) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot re-wrap DEK")
	}
	if newProvider == nil {
		return fmt.Errorf("re-wrap DEK: new key provider must not be nil")
	}

	newKEK, err := newProvider.KEK()
	if err != nil {
		return fmt.Errorf("re-wrap DEK: derive KEK from %s provider: %w", newProvider.Name(), err)
	}
	defer wipeBytes(newKEK)
	if len(newKEK) != crypto.KEKSize {
		return fmt.Errorf("re-wrap DEK: %s provider returned a %d-byte KEK, expected %d", newProvider.Name(), len(newKEK), crypto.KEKSize)
	}

	wrapped, err := wrapKey(km.currentDEK, newKEK)
	if err != nil {
		return fmt.Errorf("re-wrap DEK: wrap DEK with new KEK: %w", err)
	}

	pendingDEKPath := km.dekPath + ".pending"
	if err := securefiles.SecureWriteFile(km.baseDir, pendingDEKPath, wrapped, 0600); err != nil {
		return fmt.Errorf("re-wrap DEK: write pending DEK: %w", err)
	}
	pendingPath := filepath.Join(km.baseDir, pendingDEKPath)
	activePath := filepath.Join(km.baseDir, km.dekPath)
	if err := os.Rename(pendingPath, activePath); err != nil {
		_ = os.Remove(pendingPath)
		return fmt.Errorf("re-wrap DEK: promote pending DEK to active: %w", err)
	}
	return nil
}
