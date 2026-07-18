//go:build darwin

package securefiles

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecureWriteFile_S27_ChmodError_DevNull exercises the f.Chmod error branch in
// SecureWriteFile (lines 121-124). /dev/null is a character special device owned by
// root; a non-root process can open it for writing (O_WRONLY succeeds) but fchmod on
// it returns EPERM, triggering the Chmod error return before the Write is ever attempted.
//
// Using /dev as the base and "null" as the path passes the isPathInsideBase containment
// check while reliably triggering the fchmod failure.
func TestSecureWriteFile_S27_ChmodError_DevNull(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chmod device nodes — chmod error path not reachable as root")
	}
	// /dev/null is a character device owned by root. Opening it with
	// O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW succeeds; the subsequent fchmod fails.
	err := SecureWriteFile("/dev", "null", []byte("test"), 0644)
	require.Error(t, err, "SecureWriteFile must fail when fchmod on the device node returns EPERM")
	// The error originates from f.Chmod — not from Open or Write.
	assert.NotContains(t, err.Error(), "access denied", "must not be a containment error")
}

// TestSecureWriteFileSync_S27_ChmodError_DevNull exercises the f.Chmod error branch in
// SecureWriteFileSync (lines 149-152). Same mechanism as the SecureWriteFile variant:
// /dev/null can be opened for writing by a non-root user but fchmod on it fails with EPERM.
// The Sync call (lines 157-160) is never reached because the function returns early at Chmod.
func TestSecureWriteFileSync_S27_ChmodError_DevNull(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chmod device nodes — chmod error path not reachable as root")
	}
	err := SecureWriteFileSync("/dev", "null", []byte("test"), 0644)
	require.Error(t, err, "SecureWriteFileSync must fail when fchmod on the device node returns EPERM")
	assert.NotContains(t, err.Error(), "access denied", "must not be a containment error")
}
