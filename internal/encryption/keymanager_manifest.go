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
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	return km.keySet.WithFS(manifestFS())
}

// manifestFS is the manifest's write path: the key files' fault-injectable
// durability primitives, under their own seams.
func manifestFS() keyfiles.ManifestFS {
	return keyfiles.ManifestFS{
		WriteSync: func(dir, name string, data []byte) error {
			return durableWriteSync(dir, name, data, 0600, "manifest:write")
		},
		Rename: func(oldPath, newPath string) error {
			return durableRename(oldPath, newPath, "manifest:rename")
		},
		SyncDir: func(dir string) error {
			return durableSyncDir(dir, "manifest:syncdir")
		},
	}
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

// EventKeySetRotationFinished is the audit event recorded when boot finishes an
// interrupted key operation from its staging files (ReconcileKeySet).
const EventKeySetRotationFinished = "encryption.keyset_rotation_finished"

// ReconcileKeySet is boot's manifest step (keyfiles.ReconcileKeySet): refuse
// a partial, mixed or incoherent key set; finish an interrupted operation the
// manifest proves finishable; record a completed one whose commit was lost;
// warn about leftover staging files. It must run while this Service holds the
// exclusive key lock (or the key-initialisation advisory lock), before
// RecoverInterruptedRotation and Initialize.
func (s *Service) ReconcileKeySet() error {
	res, err := keyfiles.ReconcileKeySet(s.config, s.keyBaseDir, manifestFS())
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		log.Printf("[WARN] key set: %s", w)
	}
	if res.Finished != "" {
		var renamed []string
		for _, r := range res.Renamed {
			renamed = append(renamed, r.From+" -> "+r.To)
		}
		s.recordKeySetEvent(EventKeySetRotationFinished, fmt.Sprintf(
			"boot finished an interrupted %s from its staging files (%s), as the key-set manifest recorded it",
			res.Finished, strings.Join(renamed, ", ")))
	}
	return nil
}

// recordKeySetEvent writes a key-set audit event through the Service's audit
// sink. Best-effort, like auditKeyProviderDowngrade: the key-file change it
// reports has already happened, and the WARN log line above it stays the
// record when no sink is wired or the write fails.
func (s *Service) recordKeySetEvent(eventType, description string) {
	s.auditSinkMu.RLock()
	sink := s.auditSink
	s.auditSinkMu.RUnlock()
	if sink == nil {
		return
	}
	ok := true
	event := &models.AuditEvent{
		EventType:   eventType,
		Description: description,
		Success:     &ok,
		ActorType:   "system",
		EventTime:   time.Now(),
	}
	if err := sink(context.Background(), event); err != nil {
		log.Printf("[WARN] key set: failed to write the %s audit event: %v", eventType, err)
	}
}
