//go:build linux

package integrity

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// fsVerityFlag is FS_VERITY_FL from <linux/fs.h>: set in the FS_IOC_GETFLAGS
// result when fs-verity is enabled on the file.
const fsVerityFlag = 0x00100000

type platformFSVerity struct{}

// Enabled reads the file's inode flags. An ioctl failure (a filesystem
// without the flag interface) is an error, so the line becomes unknown.
func (platformFSVerity) Enabled(path string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the running binary
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS) //nolint:gosec // G115: fd fits int
	if err != nil {
		return false, fmt.Errorf("FS_IOC_GETFLAGS: %w", err)
	}
	return flags&fsVerityFlag != 0, nil
}
