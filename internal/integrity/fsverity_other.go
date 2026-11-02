//go:build !linux

package integrity

import "errors"

type platformFSVerity struct{}

// Enabled is never reached on a non-Linux host (checkFSVerity returns "not
// applicable" first); it errors rather than answering, so it cannot say "ok".
func (platformFSVerity) Enabled(string) (bool, error) {
	return false, errors.New("fs-verity is Linux-only")
}
