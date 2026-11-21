package config

// key_paths.go — #4249: a relative storage.encryption key-material path is
// opened relative to the PROCESS's working directory, and so is the DEK lock
// (dek.lock, beside the DEK). Two servers on one config started from two
// directories took two lock files, neither excluded the other, and which key
// files a process used depended on where it was launched, while a relative
// storage.database.path already resolves against the config's base (#1636).
//
// The defined base for relative key paths is that same base (Load's baseDir:
// the config file's directory for an absolute config path, the working
// directory for a relative one, exactly as for database.path), recorded as
// EncryptionConfig.KeyPathBase. The values are NOT rewritten to absolute paths:
// backup archives record the configured key paths and restore matches them
// against the config, so a rewrite would make every existing archive (recorded
// as e.g. "keys/kek.salt") unrestorable. Instead the code that opens key files
// (encryption.NewService, keyfiles.InspectKeySet, the server's boot) refuses a
// relative key path it would resolve against the working directory whenever
// that is not the base, so a relative key path, and the lock beside it, can
// only ever mean one place. Load itself does not refuse: it also parses
// configs that never open a key.

import (
	"fmt"
	"os"
	"path/filepath"
)

// keyMaterialPaths lists every key-material path e configures, by config key:
// the DEK, the KEK salt and, for the primary key provider and each fallback,
// its wrapped KEK blob, Shamir share files and raw KEK file.
func (e *EncryptionConfig) keyMaterialPaths() [][2]string {
	out := [][2]string{
		{"storage.encryption.dek_path", e.DEKPath},
		{"storage.encryption.salt_path", e.EffectiveSaltPath()}, // #4395: unused by a non-password provider
	}
	add := func(prefix string, kp *KeyProviderConfig) {
		out = append(out,
			[2]string{prefix + ".wrapped_key_path", kp.WrappedKeyPath},
			[2]string{prefix + ".file_path", kp.FilePath})
		for i, s := range kp.ShamirShareFiles {
			out = append(out, [2]string{fmt.Sprintf("%s.shamir_share_files[%d]", prefix, i), s})
		}
	}
	add("storage.encryption.key_provider", &e.KeyProvider)
	for i := range e.KeyProvider.Fallbacks {
		add(fmt.Sprintf("storage.encryption.key_provider.fallbacks[%d]", i), &e.KeyProvider.Fallbacks[i])
	}
	return out
}

// CheckRelativeKeyPathBase refuses a relative key-material path that a caller
// is about to resolve against the process working directory when that is not
// KeyPathBase, naming the key and both fixes. openBase is the directory the
// caller resolves relative key paths against: "." or os.Getwd() (every server
// and admin path) is judged; any other directory (backup's staging directory,
// a test's) is the caller's explicit choice and is not. Absolute and empty
// paths, disabled encryption, and a config not produced by Load (KeyPathBase
// ""), are never refused.
func (e *EncryptionConfig) CheckRelativeKeyPathBase(openBase string) error {
	if e == nil || !e.Enabled || e.KeyPathBase == "" {
		return nil
	}
	key, rel := "", ""
	for _, kv := range e.keyMaterialPaths() {
		if kv[1] != "" && !filepath.IsAbs(kv[1]) {
			key, rel = kv[0], kv[1]
			break
		}
	}
	if key == "" {
		return nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil // an unreadable cwd: nothing to compare against
	}
	if !filepath.IsAbs(openBase) {
		openBase = filepath.Join(cwd, openBase)
	}
	if !sameDir(openBase, cwd) || sameDir(e.KeyPathBase, cwd) {
		return nil
	}
	base := e.KeyPathBase
	return fmt.Errorf("%s %q is relative, and relative key paths are resolved against the config file's directory (%s), "+
		"like storage.database.path, but this process runs in %s: it would open %s and take the DEK lock beside it, "+
		"not the files every process started from %s uses (#4249). Set %s and the other key paths to absolute paths "+
		"(for example %s), or start Keyorix and every `admin` command from %s",
		key, rel, base, cwd, filepath.Join(cwd, rel), base, key, filepath.Join(base, rel), base)
}

// sameDir reports whether a and b are the same directory, following symlinks
// (macOS reports /var and /private/var for one directory).
func sameDir(a, b string) bool {
	if a == b {
		return true
	}
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	return aerr == nil && berr == nil && os.SameFile(ai, bi)
}
