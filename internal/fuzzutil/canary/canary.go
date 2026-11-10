// Package canary is the shared kit for canary-leak fuzz targets: it mints a
// replayable, high-entropy marker for each fuzz input, captures the in-process
// output channels, and searches any output for the marker in its common encodings
// and as a fragment of 8 or more bytes.
//
// It is imported only from _test.go files, including from the cli module, so it
// must stay stdlib-only (plus internal/canary, which is stdlib-only too) and must
// not import "testing". The encodings come from internal/canary; what this package
// adds is the shorter fragment window, which needs a denser alphabet to stay sound
// (see coreLen), and the capture of channels.
package canary

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	basecanary "github.com/keyorixhq/keyorix/internal/canary"
)

// Class says what a canary stands for. See internal/canary.
type Class = basecanary.Class

const (
	Secret   = basecanary.Secret
	Metadata = basecanary.Metadata
)

// Canary is one planted marker.
type Canary = basecanary.Canary

// MinWindow is the shortest contiguous run of a canary's unique core that counts
// as a leak.
const MinWindow = 8

// coreLen is the length of the unique core. The core uses a 62-letter alphabet,
// so an 8-byte window carries about 47.6 bits: a chance match against 1 MiB of
// arbitrary output with one canary's 25 windows is about 1 in 8 million, where
// the same window over hex would be 1 in 170.
const coreLen = 32

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// The hostile wrapper makes the raw form differ from its JSON, URL, HTML and
// Go-quoted encodings, so a code path that encodes the value is exercised too.
const (
	hostilePrefix = "p\"\\<&>'%+ /é"
	hostileSuffix = "é/ +%'>&<\\\"s"
)

// New derives a canary from seed and label. Deriving it from the fuzz input
// instead of crypto/rand means a saved input replays the same bytes.
func New(label string, class Class, seed []byte, hostile bool) Canary {
	core := deriveCore(label, seed)
	raw := "kxf" + class.String() + "-" + core
	if hostile {
		raw = hostilePrefix + raw + hostileSuffix
	}
	return Canary{Label: label, Class: class, Raw: raw, Core: core, Hostile: hostile}
}

func deriveCore(label string, seed []byte) string {
	h := sha256.New()
	h.Write([]byte("kx-fuzz-canary/"))
	h.Write([]byte(strconv.Itoa(len(label))))
	h.Write([]byte{'/'})
	h.Write([]byte(label))
	h.Write(seed)
	state := h.Sum(nil)
	out := make([]byte, 0, coreLen)
	for len(out) < coreLen {
		for _, b := range state {
			// Rejecting 248..255 keeps the alphabet uniform.
			if b < 248 && len(out) < coreLen {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
		next := sha256.Sum256(state)
		state = next[:]
	}
	return string(out)
}

// Hit is one detection.
type Hit struct {
	Channel string
	Label   string
	Class   Class
	Variant string
	Offset  int
	Snippet string // the match masked after 4 bytes, with up to 16 bytes of context
}

func (h Hit) String() string {
	return fmt.Sprintf("channel=%s label=%s class=%s variant=%s offset=%d snippet=%s", h.Channel, h.Label, h.Class, h.Variant, h.Offset, h.Snippet)
}

// Scanner searches byte slices for its canaries in one linear pass: every needle
// is indexed by its first 8 bytes, so the cost does not grow with the number of
// canaries or encodings.
//
// Detected forms: every whole-value encoding from internal/canary (raw, JSON, URL
// query and path, double URL, HTML, Go-quoted, hex, base64 std/url with and without
// padding, basic-auth); any run of MinWindow or more bytes of the core, which also
// covers the JSON, URL and HTML forms of a fragment because the core's alphabet
// needs no escaping; the same run lower-cased or upper-cased, because an error path
// that normalises its input before quoting it is a real shape (a window of the
// folded core still carries about 41 bits); hex of any such fragment; and base64 of a
// fragment when it spans three aligned groups (9 or more bytes of the core). It does
// not detect a base64 fragment shorter than that, a fragment shorter than MinWindow,
// or a value that was compressed, encrypted or hashed.
type Scanner struct {
	cans    []Canary
	needles []needle
	byKey   map[uint64][]int
}

type needle struct {
	canary int
	name   string
	b      []byte
	window bool
}

// NewScanner returns a scanner for cs.
func NewScanner(cs ...Canary) *Scanner {
	s := &Scanner{byKey: map[uint64][]int{}}
	for _, c := range cs {
		s.Add(c)
	}
	return s
}

// Add registers one more canary.
func (s *Scanner) Add(c Canary) {
	i := len(s.cans)
	s.cans = append(s.cans, c)
	seen := map[string]bool{}
	add := func(name string, b []byte, window bool) {
		if len(b) < 8 || seen[string(b)] {
			return
		}
		seen[string(b)] = true
		k := binary.LittleEndian.Uint64(b)
		s.byKey[k] = append(s.byKey[k], len(s.needles))
		s.needles = append(s.needles, needle{canary: i, name: name, b: b, window: window})
	}
	for _, v := range c.Variants() {
		add(v.Name, v.Bytes, false)
	}
	add("raw-lower", []byte(strings.ToLower(c.Raw)), false)
	add("raw-upper", []byte(strings.ToUpper(c.Raw)), false)
	core := []byte(c.Core)
	lower, upper := bytes.ToLower(core), bytes.ToUpper(core)
	for k := 0; k+MinWindow <= len(core); k++ {
		frag := core[k : k+MinWindow]
		add("core-window", frag, true)
		add("core-window-lower", lower[k:k+MinWindow], true)
		add("core-window-upper", upper[k:k+MinWindow], true)
		add("hex-window", []byte(hex.EncodeToString(frag)), true)
		add("hex-window", []byte(strings.ToUpper(hex.EncodeToString(frag))), true)
	}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		for phase := range 3 {
			run := alignedBase64(e, core, phase)
			for k := 0; k+12 <= len(run); k += 4 {
				add("b64-window", []byte(run[k:k+12]), true)
			}
		}
	}
}

// alignedBase64 returns the base64 groups that lie entirely inside core when core
// starts at byte offset phase of a larger encoded stream.
func alignedBase64(e *base64.Encoding, core []byte, phase int) string {
	full := e.EncodeToString(append(make([]byte, phase), core...))
	first := (phase + 2) / 3
	last := (phase + len(core)) / 3
	if last <= first {
		return ""
	}
	return full[first*4 : last*4]
}

// Canaries returns the registered canaries.
func (s *Scanner) Canaries() []Canary { return append([]Canary(nil), s.cans...) }

// Scan returns every registered canary found in data, one hit per (canary,
// variant). A fragment hit is reported only for a canary with no whole-value hit,
// so a plain leak is not counted 25 times and a truncated one is still reported.
func (s *Scanner) Scan(channel string, data []byte) []Hit {
	var hits, fragments []Hit
	whole := map[int]bool{}
	seenNeedle := map[int]bool{}
	seenFragment := map[int]bool{}
	for off := 0; off+8 <= len(data); off++ {
		list, ok := s.byKey[binary.LittleEndian.Uint64(data[off:])]
		if !ok {
			continue
		}
		for _, ni := range list {
			n := s.needles[ni]
			if seenNeedle[ni] || !bytes.HasPrefix(data[off:], n.b) {
				continue
			}
			seenNeedle[ni] = true
			c := s.cans[n.canary]
			hit := Hit{Channel: channel, Label: c.Label, Class: c.Class, Variant: n.name, Offset: off, Snippet: maskedSnippet(data, off, len(n.b))}
			if n.window {
				if !seenFragment[n.canary] {
					seenFragment[n.canary] = true
					fragments = append(fragments, hit)
				}
				continue
			}
			whole[n.canary] = true
			hits = append(hits, hit)
		}
	}
	for _, f := range fragments {
		if !whole[s.indexOf(f.Label)] {
			hits = append(hits, f)
		}
	}
	return hits
}

func (s *Scanner) indexOf(label string) int {
	for i, c := range s.cans {
		if c.Label == label {
			return i
		}
	}
	return -1
}

// ScanAll scans every output.
func (s *Scanner) ScanAll(outputs []Output) []Hit {
	var hits []Hit
	for _, o := range outputs {
		hits = append(hits, s.Scan(o.Channel, o.Data)...)
	}
	return hits
}

func maskedSnippet(data []byte, off, n int) string {
	lo := max(off-16, 0)
	hi := min(off+n+16, len(data))
	keep := min(4, n)
	return strconv.QuoteToASCII(string(data[lo:off])) + " [" + strconv.QuoteToASCII(string(data[off:off+keep])) + fmt.Sprintf("..+%d] ", n-keep) + strconv.QuoteToASCII(string(data[off+n:hi]))
}

// Rule permits one kind of hit. An empty field matches anything, so a rule should
// name every field it can. Origin is the harness's name for what produced the
// output (a route, an operation or a CLI vector). A Channel ending in "*" matches
// by prefix. MetadataOnly restricts the rule to Metadata-class canaries. A canary
// whose label starts with DenyLabelPrefix is not covered: it lets a rule permit the
// caller's own fields while denying a value the caller never sent.
type Rule struct {
	ID, Channel, Origin, Label, Why string
	DenyLabelPrefix                 string
	MetadataOnly                    bool
}

func (r Rule) matchesChannel(channel string) bool {
	if prefix, ok := strings.CutSuffix(r.Channel, "*"); ok {
		return strings.HasPrefix(channel, prefix)
	}
	return r.Channel == "" || r.Channel == channel
}

// Allowlist is the explicit list of places a canary may legitimately appear. Hits
// matching no rule are findings.
type Allowlist struct {
	rules []Rule
	used  map[string]bool
}

// NewAllowlist returns an allowlist of rules.
func NewAllowlist(rules ...Rule) *Allowlist {
	return &Allowlist{rules: rules, used: map[string]bool{}}
}

// With returns a new allowlist holding the receiver's rules followed by extra ones,
// so a backend-specific target can extend a shared base without reconstructing it.
func (a *Allowlist) With(rules ...Rule) *Allowlist {
	combined := make([]Rule, 0, len(a.rules)+len(rules))
	combined = append(combined, a.rules...)
	combined = append(combined, rules...)
	return NewAllowlist(combined...)
}

// Permit returns the matching rule's ID, recording that it was used, or "".
func (a *Allowlist) Permit(h Hit, origin string) string {
	for _, r := range a.rules {
		if r.MetadataOnly && h.Class != Metadata {
			continue
		}
		if r.DenyLabelPrefix != "" && strings.HasPrefix(h.Label, r.DenyLabelPrefix) {
			continue
		}
		if r.matchesChannel(h.Channel) && (r.Origin == "" || r.Origin == origin) && (r.Label == "" || r.Label == h.Label) {
			a.used[r.ID] = true
			return r.ID
		}
	}
	return ""
}

// Unused returns the IDs of rules no hit has used.
func (a *Allowlist) Unused() []string {
	var out []string
	for _, r := range a.rules {
		if !a.used[r.ID] {
			out = append(out, r.ID)
		}
	}
	return out
}
