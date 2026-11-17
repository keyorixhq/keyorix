//go:build !linux && !darwin

package resguard

import "os"

// statBlocks is unavailable off Linux/macOS; sparse-vs-allocated collapses to
// logical bytes only.
func statBlocks(info os.FileInfo) int64 { return 0 }
