package keyfiles

import (
	"errors"
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
)

// stagingFile is one rotation-staging path, as configured.
type stagingFile struct {
	label string
	path  string
	salt  bool
}

// rotationStaging lists the ".pending" rotation-staging siblings of the KEK
// salt and the wrapped DEK. Registry and PendingRotationFiles both read it, so
// what a backup refuses is exactly what it would otherwise have archived.
func rotationStaging(enc *config.EncryptionConfig) []stagingFile {
	var files []stagingFile
	// EffectiveSaltPath: a non-password install has no salt rotation, so a
	// kek.salt.pending left from its password days is not a rotation in
	// progress (#4504 L1).
	if salt := enc.EffectiveSaltPath(); salt != "" {
		files = append(files, stagingFile{label: "KEK salt rotation-staging", path: salt + ".pending", salt: true})
	}
	if enc.DEKPath != "" {
		files = append(files, stagingFile{label: "DEK rotation-staging", path: enc.DEKPath + ".pending"})
	}
	return files
}

// BackupRefusedReasonStagingFile names "admin backup is refused because a
// rotation-staging file is present" (#4105) for machines: the reason= token of
// the backup's structured stderr line and the reason of the server's
// security.backup_refused status in GET /api/v1/system/info, so a monitor can
// match one string for both.
const BackupRefusedReasonStagingFile = "key-rotation-staging-file"

// PendingRotationFile is a rotation-staging file present on disk.
type PendingRotationFile struct {
	Path string
	// Salt: the file is the KEK salt's staging file. Boot finishes a rotation
	// that needs it and otherwise leaves it in place with a warning, while it
	// always settles the DEK's staging file (promotes or discards it).
	Salt bool
}

// PendingRotationFiles returns the rotation-staging files currently present
// under baseDir, in Registry's order: a key rotation is running or was
// interrupted. A stat failure other than "does not exist" is returned, so a
// caller refusing on this result fails closed.
func PendingRotationFiles(enc *config.EncryptionConfig, baseDir string) ([]PendingRotationFile, error) {
	if enc == nil {
		return nil, nil
	}
	var found []PendingRotationFile
	for _, s := range rotationStaging(enc) {
		clean, err := SafePath(s.label, s.path)
		if err != nil {
			return nil, err
		}
		full := resolve(baseDir, clean)
		if _, err := os.Stat(full); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("check %s: %w", s.label, err)
		}
		found = append(found, PendingRotationFile{Path: full, Salt: s.salt})
	}
	return found, nil
}
