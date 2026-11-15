//go:build linux || darwin

package resguard

import (
	"os"
	"syscall"
)

// statBlocks returns the allocated 512-byte block count from the underlying
// stat, so a sparse file (logical size huge, blocks small) and a fully-written
// file (blocks ≈ size/512) are told apart — a zip/sparse amplifier shows up in
// bytes but not blocks, which is itself a signal worth keeping.
func statBlocks(info os.FileInfo) int64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Blocks
	}
	return 0
}
