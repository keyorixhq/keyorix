package verifierflip

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"sort"
)

// sample returns up to max distinct indices in [0,n): all of them when
// n <= max, otherwise the first and last edge indices plus a seeded uniform
// sample.
func sample(n, max, edge int, rng *rand.Rand) []int {
	if n <= max {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	set := map[int]struct{}{}
	for i := 0; i < edge && i < n; i++ {
		set[i] = struct{}{}
		set[n-1-i] = struct{}{}
	}
	for len(set) < max {
		set[rng.IntN(n)] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func generate(t Target, o Options, rng *rand.Rand, emit func(mutation)) {
	a := t.Artifact
	n := len(a)

	// 1. every single bit (or the PREREG sample).
	for _, bit := range sample(n*8, o.MaxBitFlips, 512*8, rng) {
		b := append([]byte(nil), a...)
		b[bit/8] ^= 1 << (bit % 8)
		emit(mutation{fmt.Sprintf("bitflip@%d.%d", bit/8, bit%8), b, bit / 8})
	}

	// 2. truncation to every prefix length.
	for _, l := range sample(n, 4096, 256, rng) {
		emit(mutation{fmt.Sprintf("truncate@%d", l), append([]byte(nil), a[:l]...), -1})
	}

	// 3. extension.
	for _, x := range []byte{0x00, 0xff, '\n', ' '} {
		emit(mutation{fmt.Sprintf("extend+0x%02x", x), append(append([]byte(nil), a...), x), -1})
	}
	emit(mutation{"extend+self", append(append([]byte(nil), a...), a...), -1})
	r64 := make([]byte, 64)
	for i := range r64 {
		r64[i] = byte(rng.UintN(256) & 0xff) // UintN(256) < 256, the mask only makes the range visible to gosec G115
	}
	emit(mutation{"extend+rand64", append(append([]byte(nil), a...), r64...), -1})
	emit(mutation{"prepend+0x00", append([]byte{0}, a...), -1})
	emit(mutation{"prepend+space", append([]byte{' '}, a...), -1})

	// 4. reorder.
	for _, i := range sample(n/8, 4096, 64, rng) {
		if (i+2)*8 > n {
			continue
		}
		b := append([]byte(nil), a...)
		copy(b[i*8:i*8+8], a[i*8+8:i*8+16])
		copy(b[i*8+8:i*8+16], a[i*8:i*8+8])
		emit(mutation{fmt.Sprintf("swap8@%d", i*8), b, -1})
	}
	rev := append([]byte(nil), a...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	emit(mutation{"reverse", rev, -1})
	if n >= 2 {
		h := n / 2
		emit(mutation{"swap-halves", append(append([]byte(nil), a[h:]...), a[:h]...), -1})
		emit(mutation{"rotate1", append(append([]byte(nil), a[1:]...), a[0]), -1})
	}
	for si, sep := range t.Seps {
		parts := bytes.Split(a, sep)
		for i := range parts {
			for j := i + 1; j < len(parts); j++ {
				p := append([][]byte(nil), parts...)
				p[i], p[j] = p[j], p[i]
				emit(mutation{fmt.Sprintf("fieldswap[%d]@%d,%d", si, i, j), bytes.Join(p, sep), -1})
			}
		}
		for i := range parts {
			p := append(append([][]byte(nil), parts[:i]...), parts[i+1:]...)
			emit(mutation{fmt.Sprintf("fielddrop[%d]@%d", si, i), bytes.Join(p, sep), -1})
			d := append(append(append([][]byte(nil), parts[:i+1]...), parts[i]), parts[i+1:]...)
			emit(mutation{fmt.Sprintf("fielddup[%d]@%d", si, i), bytes.Join(d, sep), -1})
		}
	}

	// 5. delete / insert one byte.
	for _, i := range sample(n, 4096, 256, rng) {
		emit(mutation{fmt.Sprintf("del@%d", i), append(append([]byte(nil), a[:i]...), a[i+1:]...), i})
		emit(mutation{fmt.Sprintf("ins0@%d", i), append(append(append([]byte(nil), a[:i]...), 0), a[i:]...), i})
	}

	// 6. duplicate an 8-byte block.
	for _, i := range sample(n/8, 1024, 32, rng) {
		if (i+1)*8 > n {
			continue
		}
		blk := a[i*8 : i*8+8]
		emit(mutation{fmt.Sprintf("dup8@%d", i*8), append(append(append([]byte(nil), a[:i*8+8]...), blk...), a[i*8+8:]...), -1})
	}
}
