package securefiles

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// CreateFile writes data to a NEW file at dir/name. It refuses to write through a
// symlink at name (O_NOFOLLOW via SecureOpenBeneath) and refuses to overwrite a
// pre-existing path (O_EXCL). This is the default, safe mode for an operator-supplied
// output path (compliance export/inventory/controls --csv, trust keygen) that might
// otherwise be reused by mistake.
func CreateFile(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, unix.O_CREAT|unix.O_EXCL, false)
}

// CreateFileSync writes like CreateFile but fsyncs before returning, for
// durability-critical material created for the first time (e.g. a freshly generated
// signing key from `trust keygen`) whose loss on power failure would be unrecoverable.
func CreateFileSync(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, unix.O_CREAT|unix.O_EXCL, true)
}

// WriteFile writes data to dir/name, creating it if absent or truncating it if present.
// This is the explicit opt-in mode (--force) for a scheduled or CI run that reuses a
// fixed output path. Symlink protection is unchanged from CreateFile; only the
// overwrite refusal is relaxed.
func WriteFile(dir, name string, data []byte, perm os.FileMode) error {
	return writeFile(dir, name, data, perm, unix.O_CREAT|unix.O_TRUNC, false)
}

func writeFile(dir, name string, data []byte, perm os.FileMode, extraFlags int, sync bool) error {
	path := filepath.Join(dir, name)
	f, err := SecureOpenBeneath(dir, name, unix.O_WRONLY|extraFlags, perm)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	// O_TRUNC keeps a pre-existing file's mode, and O_CREAT's mode argument is masked
	// by umask, so set the intended permissions explicitly either way.
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
