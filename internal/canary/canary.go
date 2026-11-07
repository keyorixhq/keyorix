// Package canary is the matching engine of the secret-leak canary oracle (see
// PREREG.md): it mints unique, high-entropy, hostile-charset marker values
// and detects them on any output surface in every common encoding, including
// truncated fragments.
//
// It is deliberately stdlib-only and knows nothing about Keyorix: the same
// file is copied into DashDiag (separate module) for its output-redaction
// oracle. Surfaces, allow rules and the system under test live in the callers.
package canary

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Class says what a canary stands for.
type Class int

const (
	// Secret: must appear on no surface (see PREREG.md).
	Secret Class = iota
	// Metadata: control value, expected in storage and in the response to the
	// request that carried it. Counted, never a finding.
	Metadata
)

func (c Class) String() string {
	if c == Secret {
		return "S"
	}
	return "M"
}

// WindowLen is the minimum length of a contiguous run of a canary's unique
// core that counts as a (truncated) leak. 12 hex characters = 48 bits, so a
// chance match on random data is negligible while a value cut in half still
// matches.
const WindowLen = 12

const coreLen = 24

// hostilePrefix / hostileSuffix make the raw form differ from its JSON, URL,
// HTML and Go-quoted encodings (quote, backslash, angle brackets, ampersand,
// apostrophe, percent, plus, space, slash, non-ASCII). The unique core sits
// between them.
const (
	hostilePrefix = "p\"\\<&>'%+ /é"
	hostileSuffix = "é/ +%'>&<\\\"s"
)

// Canary is one planted marker.
type Canary struct {
	Label   string
	Class   Class
	Raw     string // the full value as supplied to the system under test
	Core    string // the unique hex run inside Raw
	Hostile bool
}

// New derives a canary deterministically from (label, seed) so a replay with
// the same seed plants byte-identical values. hostile=false yields a plain
// "kxc-<core>" shape.
func New(label string, class Class, seed uint64, hostile bool) Canary {
	h := sha256.Sum256([]byte("kx-canary/" + label + "/" + strconv.FormatUint(seed, 10)))
	core := hex.EncodeToString(h[:])[:coreLen]
	raw := "kxc" + class.String() + "-" + core
	if hostile {
		raw = hostilePrefix + "kxc" + class.String() + "-" + core + hostileSuffix
	}
	return Canary{Label: label, Class: class, Raw: raw, Core: core, Hostile: hostile}
}

// Variant is one encoded form of a canary that the scanner looks for.
type Variant struct {
	Name  string
	Bytes []byte
}

// Variants returns every encoded form checked for c, other than the sliding
// core window (handled separately by the scanner). Exported so self-tests can
// plant each one.
func (c Canary) Variants() []Variant {
	raw := []byte(c.Raw)
	core := []byte(c.Core)
	var out []Variant
	add := func(n string, b []byte) {
		if len(b) > 0 {
			out = append(out, Variant{n, b})
		}
	}
	add("raw", raw)
	add("raw-core", core)
	jsonHTML, _ := json.Marshal(c.Raw) // escapes <, >, & as < ...
	add("json-html-escaped", bytes.Trim(jsonHTML, `"`))
	var nb bytes.Buffer
	enc := json.NewEncoder(&nb)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(c.Raw)
	add("json", bytes.TrimSpace(bytes.Trim(bytes.TrimSpace(nb.Bytes()), `"`)))
	add("url-query", []byte(url.QueryEscape(c.Raw)))
	add("url-path", []byte(url.PathEscape(c.Raw)))
	add("url-double", []byte(url.QueryEscape(url.QueryEscape(c.Raw))))
	add("html", []byte(html.EscapeString(c.Raw)))
	add("go-quoted", bytes.Trim([]byte(strconv.Quote(c.Raw)), `"`))
	add("hex-lower", []byte(hex.EncodeToString(raw)))
	add("hex-upper", []byte(strings.ToUpper(hex.EncodeToString(raw))))
	add("hex-core-lower", []byte(hex.EncodeToString(core)))
	for _, e := range []struct {
		n string
		e *base64.Encoding
	}{{"b64-std", base64.StdEncoding}, {"b64-url", base64.URLEncoding}, {"b64-rawstd", base64.RawStdEncoding}, {"b64-rawurl", base64.RawURLEncoding}} {
		add(e.n, []byte(e.e.EncodeToString(raw)))
	}
	// Alignment-independent base64: the run of whole 3-byte groups lying
	// entirely inside the core, for each of the 3 phases the core may start
	// at inside a larger encoded stream.
	for _, e := range []struct {
		n string
		e *base64.Encoding
	}{{"b64-std", base64.StdEncoding}, {"b64-url", base64.URLEncoding}} {
		for a := 0; a < 3; a++ {
			padded := append(make([]byte, a), core...)
			full := e.e.EncodeToString(padded)
			gs := ((a + 2) / 3) * 3
			ge := ((a + len(core)) / 3) * 3
			if ge > gs {
				add(fmt.Sprintf("%s-phase%d", e.n, a), []byte(full[(gs/3)*4:(ge/3)*4]))
			}
		}
	}
	// Basic-auth style "user:value".
	add("b64-basic-auth", []byte(base64.StdEncoding.EncodeToString([]byte("user:"+c.Raw))))
	return out
}

// Hit is one detection.
type Hit struct {
	Surface string
	Label   string
	Class   Class
	Variant string
	Offset  int
	Snippet string // redacted context: never the canary core itself in full
}

func (h Hit) Key() string { return h.Surface + "|" + h.Label + "|" + h.Variant }

// Scanner holds the planted canaries and finds them in byte slices.
//
// Matching is a single pass over the haystack: every full-variant needle is
// indexed by its first 8 bytes (a uint64 key) and every WindowLen run of every
// core by its 12 bytes, so the cost is linear in the haystack and independent
// of how many canaries or encodings are registered. (The first version ran
// bytes.Index per variant per canary and took minutes on a few-MB database
// file with ~100 canaries.)
type Scanner struct {
	cans    []Canary
	needles []needle
	byKey   map[uint64][]int32 // first 8 bytes of a needle -> needle indexes
	windows map[string]int     // 12-char core window -> index into cans
}

type needle struct {
	ci   int
	name string
	b    []byte
}

// NewScanner builds a scanner for cs.
func NewScanner(cs ...Canary) *Scanner {
	s := &Scanner{windows: map[string]int{}, byKey: map[uint64][]int32{}}
	for _, c := range cs {
		s.Add(c)
	}
	return s
}

// Add registers one more canary (e.g. a token harvested from a response).
func (s *Scanner) Add(c Canary) {
	for _, e := range s.cans {
		if e.Raw == c.Raw && e.Label == c.Label {
			return
		}
	}
	i := len(s.cans)
	s.cans = append(s.cans, c)
	seen := map[string]bool{}
	for _, v := range c.Variants() {
		if len(v.Bytes) < 8 || seen[string(v.Bytes)] {
			continue
		}
		seen[string(v.Bytes)] = true
		ni := int32(len(s.needles))
		s.needles = append(s.needles, needle{ci: i, name: v.Name, b: v.Bytes})
		k := binary.LittleEndian.Uint64(v.Bytes)
		s.byKey[k] = append(s.byKey[k], ni)
	}
	core := c.Core
	for k := 0; k+WindowLen <= len(core); k++ {
		s.windows[core[k:k+WindowLen]] = i
	}
}

// Canaries returns the registered canaries.
func (s *Scanner) Canaries() []Canary { return append([]Canary(nil), s.cans...) }

// Scan returns all hits of any registered canary in hay, de-duplicated by
// (canary, variant). The sliding-window pass reports "core-window" only when
// no full variant of the same canary matched, so a plain leak is not
// double-counted but a truncated one is still caught.
func (s *Scanner) Scan(surface string, hay []byte) []Hit {
	var hits []Hit
	full := map[int]bool{}
	got := map[int32]bool{}
	winFound := map[int]int{}
	for off := 0; off+8 <= len(hay); off++ {
		if list, ok := s.byKey[binary.LittleEndian.Uint64(hay[off:])]; ok {
			for _, ni := range list {
				if got[ni] {
					continue
				}
				n := s.needles[ni]
				if bytes.HasPrefix(hay[off:], n.b) {
					got[ni] = true
					full[n.ci] = true
					c := s.cans[n.ci]
					hits = append(hits, Hit{Surface: surface, Label: c.Label, Class: c.Class, Variant: n.name, Offset: off, Snippet: snippet(hay, off, len(n.b))})
				}
			}
		}
		if off+WindowLen <= len(hay) {
			if i, ok := s.windows[string(hay[off:off+WindowLen])]; ok {
				if _, dup := winFound[i]; !dup {
					winFound[i] = off
				}
			}
		}
	}
	idx := make([]int, 0, len(winFound))
	for i := range winFound {
		if !full[i] {
			idx = append(idx, i)
		}
	}
	sort.Ints(idx)
	for _, i := range idx {
		off := winFound[i]
		hits = append(hits, Hit{Surface: surface, Label: s.cans[i].Label, Class: s.cans[i].Class, Variant: "core-window", Offset: off, Snippet: snippet(hay, off, WindowLen)})
	}
	sort.SliceStable(hits, func(a, b int) bool { return hits[a].Offset < hits[b].Offset })
	return hits
}

// snippet returns up to 16 bytes of context on each side of the match with
// the matched bytes themselves masked to their first 4 characters, so a
// report never carries a full canary value.
func snippet(hay []byte, off, n int) string {
	lo := max(off-16, 0)
	hi := min(off+n+16, len(hay))
	var b strings.Builder
	b.WriteString(strconv.QuoteToASCII(string(hay[lo:off])))
	keep := min(4, n)
	b.WriteString(" [" + strconv.QuoteToASCII(string(hay[off:off+keep])) + fmt.Sprintf("..+%d] ", n-keep))
	b.WriteString(strconv.QuoteToASCII(string(hay[min(off+n, hi):hi])))
	return b.String()
}
