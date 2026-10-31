//go:build linux

package integrity

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// fsVerityFlag is FS_VERITY_FL from <linux/fs.h>: set in the FS_IOC_GETFLAGS
// result when fs-verity is enabled on the file.
const fsVerityFlag = 0x00100000

type platformFSVerity struct{}

// Enabled reads the file's inode flags. An ioctl failure (a filesystem
// without the flag interface) is an error, so the line becomes unknown.
func (platformFSVerity) Enabled(path string) (bool, error) {
	// A FIFO at the executable path is refused at once, not waited on: this open
	// runs before the manifest hash, so it is the first to touch the path.
	f, err := secretenv.OpenRegularNamed("running binary", path)
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
