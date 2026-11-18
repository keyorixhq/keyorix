package keyfiles

import (
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
)

// UnusedSaltPath is the path a salt_path that no configured provider reads
// resolves to under baseDir, the same path Registry recorded for it before
// #4395 dropped it from the key set; "" when salt_path is unset or used. A
// restore matches an older archive's salt entry against it (#4504 F2). The
// path is not SafePath-checked: callers only compare it, never open it.
func UnusedSaltPath(enc *config.EncryptionConfig, baseDir string) string {
	if enc == nil || enc.SaltPath == "" || enc.UsesSalt() {
		return ""
	}
	return resolve(baseDir, filepath.Clean(enc.SaltPath))
}
