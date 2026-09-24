// Package securefile is a reduced local reimplementation of the main module's
// internal/securefiles for the thin CLI (depguard forbids importing internal/* --
// see cli/internal/depguard). It provides the same three operator-facing guarantees
// credstore already established for the credentials file (final-path-component
// O_NOFOLLOW, explicit Chmod so umask can't silently widen the mode, an O_EXCL
// "create" mode that refuses to clobber an existing file) for the other places the
// thin CLI writes operator-supplied output paths: `compliance export`/`permission-
// baseline`/`inventory`/`controls --csv` and `trust keygen`.
//
// Scope reduction from internal/securefiles, documented rather than silent: this
// package's O_NOFOLLOW guard covers only the FINAL path component, not every
// intermediate directory component internal/securefiles's SecureOpenBeneath walks.
// The thin CLI's own credstore package already made and documented this exact
// trade-off for the credentials file; the operator-supplied --output/--dir paths
// here carry the same risk profile (a local CLI invocation, not a multi-tenant
// server path), so the reduced guard is consistent with the codebase's own existing
// precedent rather than a new gap.
package securefile

import (
	"fmt"
	"os"
)

// CreateFile writes data to a NEW file at dir/name, refusing to traverse a symlink
// at the final path component (noFollowFlag) and refusing to overwrite a
// pre-existing path (O_EXCL) -- the default, safe mode for an auditor-evidence
// output path an operator might otherwise reuse by mistake.
func CreateFile(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, os.O_CREATE|os.O_EXCL, false)
}

// CreateFileSync writes like CreateFile but fsyncs before returning, for
// durability-critical material created for the first time (e.g. a freshly
// generated signing key, `trust keygen`) whose loss on power failure would be
// unrecoverable.
func CreateFileSync(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, os.O_CREATE|os.O_EXCL, true)
}

// WriteFile writes data to dir/name, creating it if absent or overwriting it if
// present (O_TRUNC) -- the explicit opt-in mode (--force) for a scheduled/CI run
// that reuses a fixed output path on every invocation. Symlink protection on the
// final path component is unchanged from CreateFile; only the overwrite refusal is
// relaxed.
func WriteFile(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, os.O_CREATE|os.O_TRUNC, false)
}

func writeFile(dir, name string, data []byte, perm os.FileMode, extraFlags int, sync bool) error {
	path := dir + string(os.PathSeparator) + name
	f, err := os.OpenFile(path, os.O_WRONLY|extraFlags|noFollowFlag, perm) // #nosec G304 -- operator-supplied output path; final component symlink-protected by noFollowFlag
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	// O_TRUNC keeps a pre-existing file's mode (and O_CREAT's mode argument is
	// masked by umask on create) -- force the intended perms explicitly either way.
	if cerr := f.Chmod(perm); cerr != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", path, cerr)
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, werr)
	}
	if sync {
		if serr := f.Sync(); serr != nil {
			_ = f.Close()
			return fmt.Errorf("sync %s: %w", path, serr)
		}
	}
	return f.Close()
}
