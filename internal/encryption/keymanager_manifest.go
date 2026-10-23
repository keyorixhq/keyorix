// keymanager_manifest.go — how KeyManager's key writers keep the key-set
// manifest (internal/keyfiles/manifest.go, #2900) current.
//
// Every writer that replaces an active key file brackets the replacement:
// stageKeySet before the first rename (a failure there aborts the operation
// before anything changed), commitKeySet after the last fsync (a failure there
// is logged, not returned: the staged intent already makes the on-disk state
// classifiable, and boot's ReconcileKeySet records the commit). The manifest
// is written through the same fault-injectable durableWriteSync /
// durableRename / durableSyncDir path as the keys, under the seams
// "manifest:write", "manifest:rename" and "manifest:syncdir".
package encryption

import (
	"log"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// defaultKeySetWriter is the manifest writer for a KeyManager built without an
// encryption config: the salt and the DEK are the whole set.
func defaultKeySetWriter(baseDir, dekPath, saltPath string) *keyfiles.SetWriter {
	if dekPath == "" {
		return nil
	}
	dekFull := filepath.Join(baseDir, dekPath)
	required := []string{dekFull}
	if saltPath != "" {
		required = append([]string{filepath.Join(baseDir, saltPath)}, required...)
	}
	return keyfiles.NewSetWriterForFiles(filepath.Dir(dekFull), required...)
}

func (km *KeyManager) keySetWriter() *keyfiles.SetWriter {
	return km.keySet.WithFS(keyfiles.ManifestFS{
		WriteSync: func(dir, name string, data []byte) error {
			return durableWriteSync(dir, name, data, 0600, "manifest:write")
		},
		Rename: func(oldPath, newPath string) error {
			return durableRename(oldPath, newPath, "manifest:rename")
		},
		SyncDir: func(dir string) error {
			return durableSyncDir(dir, "manifest:syncdir")
		},
	})
}

func (km *KeyManager) saltFullPath() string { return filepath.Join(km.baseDir, km.saltPath) }

// stageKeySet records op's intent to replace files (full path → new content).
func (km *KeyManager) stageKeySet(op string, files map[string][]byte) error {
	return km.keySetWriter().StageManifest(op, files)
}

// commitKeySet records that op replaced files. Not fatal: see the file comment.
func (km *KeyManager) commitKeySet(op string, files map[string][]byte) {
	if err := km.keySetWriter().CommitManifest(op, files); err != nil {
		log.Printf("[WARN] %s: the key files were written but the key-set manifest was not updated (%v); the next server start records it", op, err)
	}
}

// commitKeySetFromDisk records the files op has just produced, hashed as they
// are on disk now; required files that are absent are skipped.
func (km *KeyManager) commitKeySetFromDisk(op string, paths []string) {
	var present []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	if err := km.keySetWriter().CommitManifestFromDisk(op, present...); err != nil {
		log.Printf("[WARN] %s: the key files were written but the key-set manifest was not updated (%v); the next server start adopts them", op, err)
	}
}
