//go:build linux

package encryption

// memresidue_attribute_linux_test.go: the attribution mode of the
// memory-residue oracle (memresidue_test.go). It answers "which line allocated
// this copy?" for every hit, so a ratchet bound can be explained and a copy
// can be wiped where it is made. Opt-in only, never part of a CI lane:
//
//	KEYORIX_MEMRESIDUE_ATTRIBUTE=1 go test ./internal/encryption/ -run '^TestMemResidueAttribute$' -count=1 -v
//
// The child samples every allocation (runtime.MemProfileRate = 1), turns the
// GC off so no copy is freed before it is looked up, runs the oracle's
// lifecycle and scans, then writes a runtime heap dump (debug.WriteHeapDump)
// and maps each hit to the heap object holding it and that object's
// allocation stack, or to a live stack frame or a data/bss segment.
//
// What it does NOT do: attribute a hit in a free heap slot or a dead stack
// region (reported as UNATTRIBUTED). With the GC off nothing is freed, so the
// hits it sees are a superset of the measure mode's; a copy present here but
// absent there was overwritten by reuse, not wiped. It relies on the runtime's
// heap dump format ("go1.7 heap dump", runtime/heapdump.go) and fails loudly
// on a tag it does not know.

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

const envMemResidueAttribute = "KEYORIX_MEMRESIDUE_ATTRIBUTE"

type heapDumpObject struct{ addr, size uint64 }

type heapDumpFrame struct {
	sp, size uint64
	fn       string
}

type heapDumpCallSite struct {
	fn, file string
	line     uint64
}

type heapDump struct {
	objects  []heapDumpObject // sorted by addr
	frames   []heapDumpFrame
	segments []heapDumpObject              // data and bss
	samples  map[uint64]uint64             // object addr -> memprof bucket
	buckets  map[uint64][]heapDumpCallSite // memprof bucket -> allocation stack
}

// heapDumpReader decodes the uvarint-framed records of runtime/heapdump.go.
type heapDumpReader struct {
	r   *bytes.Reader
	err error
}

func (h *heapDumpReader) uv() uint64 {
	if h.err != nil {
		return 0
	}
	v, err := binary.ReadUvarint(h.r)
	h.err = err
	return v
}

func (h *heapDumpReader) skip(n int) {
	for range n {
		h.uv()
	}
}

// bytesLen skips a length-prefixed byte string and returns its length.
func (h *heapDumpReader) bytesLen() uint64 {
	n := h.uv()
	if h.err == nil {
		_, h.err = h.r.Seek(int64(n), io.SeekCurrent) // #nosec G115 -- dump lengths fit in int64
	}
	return n
}

func (h *heapDumpReader) str() string {
	n := h.uv()
	if h.err != nil || n > uint64(h.r.Len()) {
		h.err = errors.Join(h.err, errors.New("heap dump: string past end"))
		return ""
	}
	b := make([]byte, n)
	_, h.err = io.ReadFull(h.r, b)
	return string(b)
}

// fields skips a (kind, offset) list ending in kind 0.
func (h *heapDumpReader) fields() {
	for h.err == nil && h.uv() != 0 {
		h.uv()
	}
}

func parseHeapDump(b []byte) (*heapDump, error) {
	const header = "go1.7 heap dump\n"
	if !bytes.HasPrefix(b, []byte(header)) {
		return nil, errors.New("heap dump: unknown header")
	}
	h := &heapDumpReader{r: bytes.NewReader(b[len(header):])}
	d := &heapDump{samples: map[uint64]uint64{}, buckets: map[uint64][]heapDumpCallSite{}}
	for h.err == nil {
		switch tag := h.uv(); tag {
		case 0: // EOF
			slices.SortFunc(d.objects, func(a, b heapDumpObject) int { return cmp.Compare(a.addr, b.addr) })
			return d, nil
		case 1: // object: addr, contents, fields
			addr := h.uv()
			d.objects = append(d.objects, heapDumpObject{addr, h.bytesLen()})
			h.fields()
		case 2: // other root: description, pointer
			h.bytesLen()
			h.uv()
		case 3: // type: addr, size, name, indirect
			h.skip(2)
			h.bytesLen()
			h.uv()
		case 4: // goroutine
			h.skip(8)
			h.bytesLen() // wait reason
			h.skip(4)
		case 5: // stack frame: sp, depth, child sp, contents, entry, pc, continpc, name, fields
			sp := h.uv()
			h.skip(2)
			size := h.bytesLen()
			h.skip(3)
			d.frames = append(d.frames, heapDumpFrame{sp, size, h.str()})
			h.fields()
		case 6: // params
			h.skip(4)
			h.bytesLen()
			h.bytesLen()
			h.uv()
		case 7, 11: // finalizer, queued finalizer
			h.skip(5)
		case 8: // itab
			h.skip(2)
		case 9: // OS thread
			h.skip(3)
		case 10: // memstats: 24 fields, PauseNs[256], NumGC
			h.skip(24 + 256 + 1)
		case 12, 13: // data, bss: addr, contents, fields
			addr := h.uv()
			d.segments = append(d.segments, heapDumpObject{addr, h.bytesLen()})
			h.fields()
		case 14: // defer
			h.skip(7)
		case 15: // panic
			h.skip(6)
		case 16: // memprof bucket: id, size, nstk, nstk x (func, file, line), allocs, frees
			id := h.uv()
			h.uv()
			n := h.uv()
			var stack []heapDumpCallSite
			for i := uint64(0); i < n && h.err == nil; i++ {
				fn, file := h.str(), h.str()
				stack = append(stack, heapDumpCallSite{fn, file, h.uv()})
			}
			h.skip(2)
			d.buckets[id] = stack
		case 17: // alloc sample: object addr, bucket
			addr := h.uv()
			d.samples[addr] = h.uv()
		default:
			return nil, fmt.Errorf("heap dump: unknown record tag %d", tag)
		}
	}
	return nil, fmt.Errorf("heap dump: %w", h.err)
}

// attribute names what holds address a.
func (d *heapDump) attribute(a uint64) string {
	i, found := slices.BinarySearchFunc(d.objects, a, func(o heapDumpObject, a uint64) int {
		switch {
		case a < o.addr:
			return 1
		case a >= o.addr+o.size:
			return -1
		}
		return 0
	})
	if found {
		o := d.objects[i]
		bucket, ok := d.samples[o.addr]
		if !ok {
			return fmt.Sprintf("heap object %#x (%d bytes, +%d), no allocation sample", o.addr, o.size, a-o.addr)
		}
		var sites []string
		for _, s := range d.buckets[bucket] {
			if strings.HasPrefix(s.fn, "runtime.") || strings.HasPrefix(s.fn, "testing.") {
				continue
			}
			sites = append(sites, fmt.Sprintf("%s (%s:%d)", s.fn, shortGoPath(s.file), s.line))
		}
		return fmt.Sprintf("heap object %d bytes, +%d, allocated at:\n\t\t%s", o.size, a-o.addr, strings.Join(sites, "\n\t\t"))
	}
	for _, f := range d.frames {
		if a >= f.sp && a < f.sp+f.size {
			return "live stack frame of " + f.fn
		}
	}
	for _, s := range d.segments {
		if a >= s.addr && a < s.addr+s.size {
			return "data/bss segment"
		}
	}
	return "UNATTRIBUTED (free heap slot or dead stack)"
}

func shortGoPath(file string) string {
	if i := strings.Index(file, "keyorix/"); i >= 0 {
		return file[i:]
	}
	if _, rest, ok := strings.Cut(file, "/src/"); ok {
		return rest
	}
	return file
}

func TestMemResidueAttribute(t *testing.T) {
	if os.Getenv(envMemResidueAttribute) == "" {
		t.Skip("attribution mode of the memory-residue oracle: set " + envMemResidueAttribute + "=1 to run it")
	}
	if err := memScanSupported(); err != nil {
		t.Skipf("memory-residue oracle unavailable: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemResidueAttributeChild$", "-test.count=1", "-test.v") // #nosec G204 -- os.Args[0] is this test binary
	cmd.Env = append(os.Environ(), envMemResidueHelper+"="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attribution child failed: %v\n%s", err, out)
	}
	t.Logf("attribution (GC off, so a superset of the measure mode's hits):\n%s", out)
}

// TestMemResidueAttributeChild is the attribution child; it does nothing unless
// the parent set KEYORIX_MEMRESIDUE_HELPER.
func TestMemResidueAttributeChild(t *testing.T) {
	dir := os.Getenv(envMemResidueHelper)
	if dir == "" {
		t.Skip("not invoked as the memory-residue attribution child")
	}
	runtime.MemProfileRate = 1
	debug.SetGCPercent(-1)

	svc, needles, claims, err := startMemResidueService(dir)
	if err != nil {
		t.Fatal(err)
	}
	live, _, err := scanProcessMemory(needles)
	if err != nil {
		t.Fatal(err)
	}
	svc.Shutdown()
	after, _, err := scanProcessMemory(needles)
	if err != nil {
		t.Fatal(err)
	}

	// The dump holds every heap object's contents, key bytes included: it is
	// read back once, after both scans, and removed.
	path := filepath.Join(dir, "heap.dump")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- path is under the parent's t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	debug.WriteHeapDump(f.Fd())
	_ = f.Close()
	raw, err := os.ReadFile(path) // #nosec G304 -- see above
	_ = os.Remove(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := parseHeapDump(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}

	claimed := map[uint64]string{}
	for _, c := range claims {
		claimed[c.Addr] = c.What + " (" + c.Claim + ")"
	}
	for _, phase := range []struct {
		name string
		hits []memHit
	}{{"live", live}, {"after Shutdown", after}} {
		t.Logf("%s: %d hit(s)", phase.name, len(phase.hits))
		for _, h := range phase.hits {
			what := d.attribute(h.Addr)
			if c, ok := claimed[h.Addr]; ok {
				what = "CLAIMED " + c + "; " + what
			}
			t.Logf("  %s %#x: %s", h.Name, h.Addr, what)
		}
	}
}
