package libconformance

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// FuzzQRCodeRoundTrip pins boombuler/barcode's QR encoder, the library pquerna/otp's
// Key.Image renders TOTP enrolment codes with (qr.Encode(url, qr.M, qr.Auto)). keyorix
// itself never calls Key.Image today (it returns the otpauth:// URI and leaves rendering
// to the client), so this target is conformance for a dormant path, not a live one.
//
// There is no QR decoder in the module graph, so the oracle carries its own, written
// from ISO/IEC 18004 independently of the encoder (tables below; layout as in Nayuki's
// reference implementation):
//
//   - O1 ROUND-TRIP: every successful Encode decodes back to exactly the content, with
//     the mode the caller asked for (Auto picks Numeric, then AlphaNumeric, then byte).
//   - O2 STRUCTURE: finder, timing, dark-module, both format-info copies (BCH-valid,
//     equal, and naming the requested error-correction level), version info for
//     versions >= 7 (BCH-valid on both copies), the symbol size 17+4v, every
//     Reed-Solomon block with zero syndromes, and the 0xEC/0x11 pad pattern.
//   - O3 MINIMAL VERSION: the chosen version is the smallest that holds the segment.
//   - O4 REJECTION SOUNDNESS: Encode fails only when the content is not encodable in
//     the requested mode, or does not fit version 40 at the requested level.
//
// Content is capped at 4 KiB, above version 40's 2953-byte byte-mode capacity, so the
// "too long" path is still exercised. That cap is an input bound, not an oracle.
//
// What this does NOT verify: encoder time or allocation; that a real camera-side reader decodes the symbol (no
// quiet-zone or scaling checks beyond the module grid); that the penalty-based mask
// choice is the optimal one (any mask is legal; the decoder reads whichever was used);
// ECI headers (the library never emits them; byte mode carries raw UTF-8, which the
// spec calls ISO-8859-1 by default, a known library choice); Structured Append, Kanji
// and mixed-mode segmentation (not produced); barcode.Scale beyond its error path.
func FuzzQRCodeRoundTrip(f *testing.F) {
	for _, s := range []string{
		"otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXP",
		"0123456789", "HELLO WORLD $%*+-./:", "hello", "", "é", "\x00\xff",
		"+12", "-0", strings.Repeat("9", 7089), strings.Repeat("A", 4296), strings.Repeat("a", 2953),
	} {
		for lvl := range 4 {
			for mode := range 4 {
				f.Add(s, byte(lvl), byte(mode))
			}
		}
	}
	f.Fuzz(func(t *testing.T, content string, lvl, mode byte) {
		if len(content) > 4<<10 {
			return
		}
		checkQRRoundTrip(t, content, qrLevels[lvl%4], qr.Encoding(mode%4), qr.Encode)
	})
}

type qrEncodeFunc func(string, qr.ErrorCorrectionLevel, qr.Encoding) (barcode.Barcode, error)

var qrLevels = [4]qr.ErrorCorrectionLevel{qr.L, qr.M, qr.Q, qr.H}

// qrLevelIndex maps a level to the row index of the tables below (L, M, Q, H).
func qrLevelIndex(l qr.ErrorCorrectionLevel) int {
	for i, v := range qrLevels {
		if v == l {
			return i
		}
	}
	panic("unknown level")
}

// ISO/IEC 18004:2015 Table 9, by level (L, M, Q, H) and version (index 0 unused).
var (
	qrECCPerBlock = [4][41]int{
		{-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
		{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
		{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
		{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	}
	qrNumBlocks = [4][41]int{
		{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
		{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
		{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
		{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
	}
	qrFormatECLBits = [4]int{1, 0, 3, 2} // L, M, Q, H
)

const qrAlnumCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

func qrRawDataModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		n := ver/7 + 2
		r -= (25*n-10)*n - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}

func qrTotalCodewords(ver int) int { return qrRawDataModules(ver) / 8 }

func qrDataCodewords(ver, li int) int {
	return qrTotalCodewords(ver) - qrECCPerBlock[li][ver]*qrNumBlocks[li][ver]
}

func qrAlignmentPositions(ver int) []int {
	if ver == 1 {
		return nil
	}
	n := ver/7 + 2
	size := 17 + 4*ver
	step := (ver*8 + n*3 + 5) / (n*4 - 4) * 2
	pos := make([]int, n)
	pos[0] = 6
	for i, p := n-1, size-7; i >= 1; i, p = i-1, p-step {
		pos[i] = p
	}
	return pos
}

// qrCharCountBits is Table 3: numeric, alphanumeric, byte by version range.
func qrCharCountBits(modeIdx, ver int) int {
	tbl := [3][3]int{{10, 12, 14}, {9, 11, 13}, {8, 16, 16}}
	switch {
	case ver <= 9:
		return tbl[modeIdx][0]
	case ver <= 26:
		return tbl[modeIdx][1]
	}
	return tbl[modeIdx][2]
}

// qrSegmentBits is the bit length of a single segment of n characters in a mode.
func qrSegmentBits(modeIdx, n, ver int) int {
	b := 4 + qrCharCountBits(modeIdx, ver)
	switch modeIdx {
	case 0:
		b += n/3*10 + [3]int{0, 4, 7}[n%3]
	case 1:
		b += n/2*11 + n%2*6
	default:
		b += n * 8
	}
	return b
}

func qrIsNumeric(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

func qrIsAlnum(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune(qrAlnumCharset, r) })
}

// qrAtoiNumeric models finding LF1-QR-numeric-sign: the library's numeric encoder
// splits the content into 3-byte groups and accepts any group strconv.Atoi parses to a
// non-negative value, so a sign survives the check ("+12", "-0", "123+45") and is dropped
// from the symbol ("+12" encodes as "012"). It returns the content the library actually
// encodes, and whether the content takes that path without being all digits. The
// oracle then demands exactly this content, so every other defect on these inputs
// still fails; TestQRFindingNumericSign goes red when the library is fixed.
func qrAtoiNumeric(content string) (string, bool) {
	if content == "" || qrIsNumeric(content) {
		return "", false
	}
	var sb strings.Builder
	for pos := 0; pos < len(content); pos += 3 {
		g := content[pos:min(pos+3, len(content))]
		v, err := strconv.Atoi(g)
		if err != nil || v < 0 {
			return "", false
		}
		fmt.Fprintf(&sb, "%0*d", len(g), v)
	}
	return sb.String(), true
}

// qrExpectedMode returns the mode index (0 numeric, 1 alnum, 2 byte) the content must be
// encoded in, or -1 when the requested mode cannot represent it.
func qrExpectedMode(content string, mode qr.Encoding) int {
	_, signed := qrAtoiNumeric(content)
	switch mode {
	case qr.Numeric:
		if qrIsNumeric(content) || signed {
			return 0
		}
	case qr.AlphaNumeric:
		if qrIsAlnum(content) {
			return 1
		}
	case qr.Unicode:
		return 2
	case qr.Auto:
		switch {
		case qrIsNumeric(content) || signed:
			return 0
		case qrIsAlnum(content):
			return 1
		}
		return 2
	}
	return -1
}

// qrSmallestVersion returns the smallest version that holds the segment, or 0.
func qrSmallestVersion(modeIdx, n, li int) int {
	for v := 1; v <= 40; v++ {
		if qrSegmentBits(modeIdx, n, v) <= qrDataCodewords(v, li)*8 {
			return v
		}
	}
	return 0
}

func checkQRRoundTrip(t *testing.T, content string, lvl qr.ErrorCorrectionLevel, mode qr.Encoding, encode qrEncodeFunc) {
	t.Helper()
	li := qrLevelIndex(lvl)
	wantMode := qrExpectedMode(content, mode)
	n := len(content)
	if wantMode == 1 || wantMode == 0 {
		n = len([]rune(content))
	}
	wantVer := 0
	if wantMode >= 0 {
		wantVer = qrSmallestVersion(wantMode, n, li)
	}
	// Auto falls through to the next mode when the content does not fit: the library
	// tries Numeric, AlphaNumeric, then byte mode in turn.
	if mode == qr.Auto {
		for wantVer == 0 && wantMode < 2 {
			wantMode++
			if wantMode == 2 {
				n = len(content)
			}
			wantVer = qrSmallestVersion(wantMode, n, li)
		}
	}

	bc, err := encode(content, lvl, mode)
	if wantMode < 0 || wantVer == 0 {
		if err == nil {
			t.Fatalf("O4 REJECTION: Encode(%q, %v, %v) succeeded, but the content is not encodable (mode %d, version %d)", content, lvl, mode, wantMode, wantVer)
		}
		return
	}
	if err != nil {
		t.Fatalf("O4 REJECTION: Encode(%q, %v, %v) failed (%v), but it fits version %d in mode %d", content, lvl, mode, err, wantVer, wantMode)
	}

	dec, err := decodeQR(bc)
	if err != nil {
		t.Fatalf("O2 STRUCTURE: Encode(%q, %v, %v) produced a symbol the reference decoder rejects: %v", content, lvl, mode, err)
	}
	if dec.level != li {
		t.Fatalf("O2 STRUCTURE: format info names level %d, requested %d (content %q)", dec.level, li, content)
	}
	wantContent := content
	if norm, signed := qrAtoiNumeric(content); signed && wantMode == 0 {
		wantContent = norm // known finding LF1-QR-numeric-sign, see qrAtoiNumeric
	}
	if dec.content != wantContent || dec.mode != wantMode {
		t.Fatalf("O1 ROUND-TRIP: Encode(%q, %v, %v) decodes to %q in mode %d (want %q in mode %d)", content, lvl, mode, dec.content, dec.mode, wantContent, wantMode)
	}
	if dec.version != wantVer {
		t.Fatalf("O3 MINIMAL-VERSION: Encode(%q, %v, %v) chose version %d, smallest that fits is %d", content, lvl, mode, dec.version, wantVer)
	}
}

type qrDecoded struct {
	version, level, mask, mode int
	content                    string
}

type qrGrid struct {
	size int
	dark func(x, y int) bool
}

func decodeQR(bc barcode.Barcode) (qrDecoded, error) {
	var d qrDecoded
	b := bc.Bounds()
	size := b.Dx()
	if size != b.Dy() || (size-17)%4 != 0 || size < 21 || size > 177 {
		return d, fmt.Errorf("symbol is %dx%d, not 17+4v square", b.Dx(), b.Dy())
	}
	d.version = (size - 17) / 4
	g := qrGrid{size: size, dark: func(x, y int) bool {
		r, gg, bb, a := bc.At(b.Min.X+x, b.Min.Y+y).RGBA()
		return r == 0 && gg == 0 && bb == 0 && a == 0xffff
	}}
	if err := qrCheckFunctionPatterns(g, d.version); err != nil {
		return d, err
	}
	li, mask, err := qrReadFormat(g)
	if err != nil {
		return d, err
	}
	d.level, d.mask = li, mask
	if d.version >= 7 {
		if err := qrCheckVersionInfo(g, d.version); err != nil {
			return d, err
		}
	}
	data, err := qrReadCodewords(g, d.version, li, mask)
	if err != nil {
		return d, err
	}
	d.mode, d.content, err = qrParseSegment(data, d.version)
	return d, err
}

func qrIsFunction(ver, size, x, y int) bool {
	switch {
	case x < 9 && y < 9, x >= size-8 && y < 9, x < 9 && y >= size-8: // finders, separators, format
		return true
	case x == 6 || y == 6:
		return true
	case ver >= 7 && ((x >= size-11 && x < size-8 && y < 6) || (y >= size-11 && y < size-8 && x < 6)):
		return true
	}
	ap := qrAlignmentPositions(ver)
	for i, ax := range ap {
		for j, ay := range ap {
			if (i == 0 && j == 0) || (i == 0 && j == len(ap)-1) || (i == len(ap)-1 && j == 0) {
				continue
			}
			if x >= ax-2 && x <= ax+2 && y >= ay-2 && y <= ay+2 {
				return true
			}
		}
	}
	return false
}

func qrCheckFunctionPatterns(g qrGrid, ver int) error {
	size := g.size
	finder := func(cx, cy int) error {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := cx+dx, cy+dy
				if x < 0 || y < 0 || x >= size || y >= size {
					continue
				}
				dist := max(abs(dx), abs(dy))
				want := dist != 2 && dist != 4
				if g.dark(x, y) != want {
					return fmt.Errorf("finder at (%d,%d): module (%d,%d) wrong", cx, cy, x, y)
				}
			}
		}
		return nil
	}
	for _, c := range [][2]int{{3, 3}, {size - 4, 3}, {3, size - 4}} {
		if err := finder(c[0], c[1]); err != nil {
			return err
		}
	}
	for i := 8; i < size-8; i++ {
		if g.dark(i, 6) != (i%2 == 0) || g.dark(6, i) != (i%2 == 0) {
			return fmt.Errorf("timing pattern wrong at %d", i)
		}
	}
	ap := qrAlignmentPositions(ver)
	for i, ax := range ap {
		for j, ay := range ap {
			if (i == 0 && j == 0) || (i == 0 && j == len(ap)-1) || (i == len(ap)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					if g.dark(ax+dx, ay+dy) != (max(abs(dx), abs(dy)) != 1) {
						return fmt.Errorf("alignment pattern at (%d,%d) wrong", ax, ay)
					}
				}
			}
		}
	}
	if !g.dark(8, size-8) {
		return errors.New("dark module missing")
	}
	return nil
}

func abs(v int) int { return max(v, -v) }

func qrFormatBits(li, mask int) int {
	data := qrFormatECLBits[li]<<3 | mask
	rem := data
	for range 10 {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return (data<<10 | rem) ^ 0x5412
}

func qrReadFormat(g qrGrid) (li, mask int, err error) {
	size := g.size
	bit := func(x, y int) int {
		if g.dark(x, y) {
			return 1
		}
		return 0
	}
	var a, b int
	for i := 0; i <= 5; i++ {
		a |= bit(8, i) << i
	}
	a |= bit(8, 7) << 6
	a |= bit(8, 8) << 7
	a |= bit(7, 8) << 8
	for i := 9; i < 15; i++ {
		a |= bit(14-i, 8) << i
	}
	for i := range 8 {
		b |= bit(size-1-i, 8) << i
	}
	for i := 8; i < 15; i++ {
		b |= bit(8, size-15+i) << i
	}
	if a != b {
		return 0, 0, fmt.Errorf("format info copies differ: %015b vs %015b", a, b)
	}
	for l := range 4 {
		for m := range 8 {
			if qrFormatBits(l, m) == a {
				return l, m, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("format info %015b is not a valid BCH codeword", a)
}

func qrCheckVersionInfo(g qrGrid, ver int) error {
	rem := ver
	for range 12 {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	want := ver<<12 | rem
	size := g.size
	for i := range 18 {
		w := (want>>i)&1 == 1
		x, y := size-11+i%3, i/3
		if g.dark(x, y) != w || g.dark(y, x) != w {
			return fmt.Errorf("version info bit %d wrong for version %d", i, ver)
		}
	}
	return nil
}

func qrMask(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

// qrReadCodewords reads, unmasks and de-interleaves the codewords, checks every block's
// Reed-Solomon syndromes, and returns the data codewords in order.
func qrReadCodewords(g qrGrid, ver, li, mask int) ([]byte, error) {
	size := g.size
	total := qrTotalCodewords(ver)
	raw := make([]byte, total)
	i := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range size {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = size - 1 - vert
				}
				if qrIsFunction(ver, size, x, y) {
					continue
				}
				if i < total*8 && g.dark(x, y) != qrMask(mask, x, y) {
					raw[i/8] |= 1 << (7 - i%8)
				}
				i++
			}
		}
	}
	if i != qrRawDataModules(ver) {
		return nil, fmt.Errorf("read %d data modules, version %d has %d", i, ver, qrRawDataModules(ver))
	}

	nb, ecc := qrNumBlocks[li][ver], qrECCPerBlock[li][ver]
	short := nb - total%nb
	shortLen := total / nb // data+ecc of a short block
	blocks := make([][]byte, nb)
	for k := range blocks {
		dl := shortLen - ecc
		if k >= short {
			dl++
		}
		blocks[k] = make([]byte, 0, dl+ecc)
	}
	p := 0
	for col := 0; col <= shortLen-ecc; col++ {
		for k := range blocks {
			dl := shortLen - ecc
			if k >= short {
				dl++
			}
			if col < dl {
				blocks[k] = append(blocks[k], raw[p])
				p++
			}
		}
	}
	for range ecc {
		for k := range blocks {
			blocks[k] = append(blocks[k], raw[p])
			p++
		}
	}
	var data []byte
	for k, blk := range blocks {
		if s := rsSyndromeNonZero(blk, ecc); s >= 0 {
			return nil, fmt.Errorf("Reed-Solomon block %d/%d has non-zero syndrome %d", k, nb, s)
		}
		data = append(data, blk[:len(blk)-ecc]...)
	}
	return data, nil
}

// GF(256) with the QR polynomial 0x11D.
var gfExp, gfLog = func() (exp [512]byte, log [256]byte) {
	x := 1
	for i := range 255 {
		exp[i] = byte(x)
		log[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsSyndromeNonZero returns the index of the first non-zero syndrome c(α^i), i < ecc,
// or -1 when the block is a valid codeword.
func rsSyndromeNonZero(blk []byte, ecc int) int {
	for i := range ecc {
		var s byte
		a := gfExp[i]
		for _, c := range blk {
			s = gfMul(s, a) ^ c
		}
		if s != 0 {
			return i
		}
	}
	return -1
}

func qrParseSegment(data []byte, ver int) (modeIdx int, content string, err error) {
	pos := 0
	read := func(n int) (int, error) {
		if pos+n > len(data)*8 {
			return 0, errors.New("bit stream truncated")
		}
		v := 0
		for range n {
			v = v<<1 | int(data[pos/8]>>(7-pos%8)&1)
			pos++
		}
		return v, nil
	}
	m, err := read(4)
	if err != nil {
		return 0, "", err
	}
	switch m {
	case 1:
		modeIdx = 0
	case 2:
		modeIdx = 1
	case 4:
		modeIdx = 2
	default:
		return 0, "", fmt.Errorf("unexpected mode indicator %04b", m)
	}
	n, err := read(qrCharCountBits(modeIdx, ver))
	if err != nil {
		return 0, "", err
	}
	var sb strings.Builder
	switch modeIdx {
	case 0:
		for left := n; left > 0; left -= 3 {
			k := min(left, 3)
			v, err := read([4]int{0, 4, 7, 10}[k])
			if err != nil {
				return 0, "", err
			}
			if v >= [4]int{1, 10, 100, 1000}[k] {
				return 0, "", fmt.Errorf("numeric group %d out of range for %d digits", v, k)
			}
			fmt.Fprintf(&sb, "%0*d", k, v)
		}
	case 1:
		for left := n; left > 0; left -= 2 {
			if left == 1 {
				v, err := read(6)
				if err != nil {
					return 0, "", err
				}
				if v >= 45 {
					return 0, "", fmt.Errorf("alphanumeric value %d out of range", v)
				}
				sb.WriteByte(qrAlnumCharset[v])
				break
			}
			v, err := read(11)
			if err != nil {
				return 0, "", err
			}
			if v >= 45*45 {
				return 0, "", fmt.Errorf("alphanumeric pair %d out of range", v)
			}
			sb.WriteByte(qrAlnumCharset[v/45])
			sb.WriteByte(qrAlnumCharset[v%45])
		}
	default:
		for range n {
			v, err := read(8)
			if err != nil {
				return 0, "", err
			}
			sb.WriteByte(byte(v))
		}
	}
	// Terminator (up to 4 zero bits), zero bits to the byte boundary, then 0xEC/0x11 pads.
	for k := 0; k < 4 && pos < len(data)*8; k++ {
		if v, _ := read(1); v != 0 {
			return 0, "", errors.New("non-zero terminator bit")
		}
	}
	for pos%8 != 0 {
		if v, _ := read(1); v != 0 {
			return 0, "", errors.New("non-zero bit before byte boundary")
		}
	}
	for k, b := range data[pos/8:] {
		if want := [2]byte{0xEC, 0x11}[k%2]; b != want {
			return 0, "", fmt.Errorf("pad byte %d is %#x, want %#x", k, b, want)
		}
	}
	return modeIdx, sb.String(), nil
}
