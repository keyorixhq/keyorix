// unwrap_hints.go — names what an interrupted rotate-kek or migrate-provider
// left in the key directory when the DEK does not unwrap.
//
// Both commands, killed at one point, leave dek.key wrapped under a KEK the
// configuration does not produce yet, and every later start then fails with
// the same "wrong passphrase or corrupted key file" error. The one hint (the
// leftover file and what to do with it) was in the error of the run that was
// killed, which is lost (REVIEW-ENCRYPTIONOPS-1 R3/R4). This only adds text to
// that error: what Initialize accepts or refuses is unchanged.
package encryption

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// keyRotationRunbookRecovery is the runbook section the hints point at.
const keyRotationRunbookRecovery = `docs/operator/key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider"`

// withInterruptedKeyOpHints appends to err, a failed DEK unwrap, one line per
// leftover of an interrupted key operation found beside the key files, each
// with the recovery from the runbook. err is returned unchanged when there is
// none.
func (km *KeyManager) withInterruptedKeyOpHints(err error) error {
	var hints []string
	dekFull := filepath.Join(km.baseDir, km.dekPath)
	if km.saltPath != "" {
		saltFull := filepath.Join(km.baseDir, km.saltPath)
		pendingSalt := saltFull + ".pending"
		if regularFileExists(pendingSalt) {
			if regularFileExists(dekFull + ".pending") {
				hints = append(hints, fmt.Sprintf("%s and %s.pending exist: a rotate-kek was interrupted before it replaced %s, which is still wrapped under the previous passphrase. "+
					"Do not rename them: start with the previous passphrase and re-run rotate-kek (%s)", pendingSalt, dekFull, dekFull, keyRotationRunbookRecovery))
			} else {
				hints = append(hints, fmt.Sprintf("%s exists: a rotate-kek was interrupted after it re-wrapped %s under the new passphrase and before it replaced %s. "+
					"With the server stopped, run `mv %s %s` and start with the NEW passphrase (%s)", pendingSalt, dekFull, saltFull, pendingSalt, saltFull, keyRotationRunbookRecovery))
			}
		}
	}
	if backup := newestMigrateBackup(dekFull); backup != "" {
		hints = append(hints, fmt.Sprintf("%s is the newest migrate-provider backup: if a migrate-provider was interrupted after it re-wrapped %s (or finished and the configuration was not updated), %s is wrapped under the TARGET provider. "+
			"Set storage.encryption.key_provider to the provider you migrated to and start again; to go back afterwards, run `keyorix-server admin encryption migrate-provider --to-type <previous provider> --confirm`. Keep the backup until that works (%s)",
			backup, dekFull, dekFull, keyRotationRunbookRecovery))
	}
	if len(hints) == 0 {
		return err
	}
	return fmt.Errorf("%w\n  - %s", err, strings.Join(hints, "\n  - "))
}

// regularFileExists reports whether path is a regular file. A symlink or
// anything else is not named in a recovery hint.
func regularFileExists(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// newestMigrateBackup returns the most recently modified
// "<dek>.migrate-backup.*" file beside dekFull (not a "*.restoring" staging
// copy of one), or "" when there is none or the directory cannot be read.
func newestMigrateBackup(dekFull string) string {
	dir := filepath.Dir(dekFull)
	prefix := filepath.Base(dekFull) + ".migrate-backup."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var newest string
	var newestInfo fs.FileInfo
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(name, prefix) || strings.HasSuffix(name, ".restoring") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newestInfo == nil || info.ModTime().After(newestInfo.ModTime()) ||
			(info.ModTime().Equal(newestInfo.ModTime()) && name > filepath.Base(newest)) {
			newest, newestInfo = filepath.Join(dir, name), info
		}
	}
	return newest
}
