package resguard

import (
	"io/fs"
	"os"
	"path/filepath"
)

// diskSnap is a count of what lives under a directory tree at one instant.
type diskSnap struct {
	files    int
	dirs     int
	symlinks int
	bytes    int64 // sum of regular-file logical sizes
	blocks   int64 // sum of allocated 512-byte blocks (sparse-aware); 0 if unavailable
}

// walkDisk snapshots dir. A missing dir is an empty snapshot, not an error — a
// harness may create its TempDir lazily. Symlinks are counted, never followed.
func walkDisk(dir string) diskSnap {
	var s diskSnap
	if dir == "" {
		return s
	}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort the whole walk
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			s.symlinks++
		case d.IsDir():
			s.dirs++
		default:
			s.files++
			if info, e := d.Info(); e == nil {
				s.bytes += info.Size()
				s.blocks += allocatedBlocks(info)
			}
		}
		return nil
	})
	return s
}

// sub returns the growth of b over a (after minus before). Counts can go
// negative if the tree shrank; callers interested in growth clamp at zero.
func (b diskSnap) sub(a diskSnap) diskSnap {
	return diskSnap{
		files:    b.files - a.files,
		dirs:     b.dirs - a.dirs,
		symlinks: b.symlinks - a.symlinks,
		bytes:    b.bytes - a.bytes,
		blocks:   b.blocks - a.blocks,
	}
}

// allocatedBlocks returns the 512-byte blocks actually allocated to a file when
// the OS exposes it (Linux/macOS stat Blocks), so a sparse file's real on-disk
// footprint is distinguishable from its logical size. 0 when unavailable; see
// diskstat_*.go.
func allocatedBlocks(info os.FileInfo) int64 { return statBlocks(info) }
