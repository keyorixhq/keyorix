//go:build linux

package encryption

// memresidue_scan_linux_test.go: the Linux half of the memory-residue oracle
// (memresidue_test.go). It walks /proc/self/maps and reads every readable
// mapping through /proc/self/mem, reporting each place a needle occurs.

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

const memScanChunk = 1 << 20

// memScanSupported reports whether this process can read its own memory.
func memScanSupported() error {
	f, err := os.Open("/proc/self/mem")
	if err != nil {
		return fmt.Errorf("/proc/self/mem not readable: %w", err)
	}
	return f.Close()
}

type memRegion struct {
	start, end uint64
	label      string
}

func readableRegions() ([]memRegion, error) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []memRegion
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		// 7f0000000000-7f0000021000 rw-p 00000000 00:00 0   [heap]
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue
		}
		label := "anon"
		if len(fields) >= 6 {
			label = fields[5]
		}
		if label == "[vvar]" || label == "[vsyscall]" || label == "[vdso]" {
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		s, e1 := strconv.ParseUint(lo, 16, 64)
		e, e2 := strconv.ParseUint(hi, 16, 64)
		if e1 != nil || e2 != nil || e <= s {
			continue
		}
		out = append(out, memRegion{s, e, label})
	}
	return out, sc.Err()
}

// scanProcessMemory returns every occurrence of every needle in this process's
// readable memory, and the number of bytes scanned. A needle is matched by its
// masked 8-byte prefix, then confirmed by SHA-256 over the whole window.
func scanProcessMemory(needles []memNeedle) (hits []memHit, scanned uint64, err error) {
	regions, err := readableRegions()
	if err != nil {
		return nil, 0, err
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = mem.Close() }()

	maxN := 0
	for _, n := range needles {
		maxN = max(maxN, n.length)
	}
	buf := make([]byte, memScanChunk+maxN)
	// The scanner's own buffer holds copies of whatever it read last; it must
	// neither be reported nor outlive the scan holding key bytes.
	defer clear(buf)
	bufLo := uint64(uintptr(unsafe.Pointer(&buf[0])))
	bufHi := bufLo + uint64(len(buf))
	for _, r := range regions {
		for off := r.start; off < r.end; off += memScanChunk {
			want := min(uint64(len(buf)), r.end-off)
			n, rerr := mem.ReadAt(buf[:want], int64(off)) // #nosec G115 -- user-space addresses fit in int64
			if n <= 0 && rerr != nil {
				break // unreadable tail of this mapping (EIO); move on
			}
			scanned += uint64(n)
			limit := min(n, memScanChunk) // the maxN tail belongs to the next chunk
			for i := range limit {
				for _, nd := range needles {
					if i+nd.length > n || i+8 > n {
						continue
					}
					if binary.LittleEndian.Uint64(buf[i:])^nd.mask != nd.masked {
						continue
					}
					if a := off + uint64(i); a >= bufLo && a < bufHi {
						continue
					}
					if sha256.Sum256(buf[i:i+nd.length]) == nd.sum {
						hits = append(hits, memHit{Name: nd.name, Region: r.label, Addr: off + uint64(i)})
					}
				}
			}
		}
	}
	return hits, scanned, nil
}
