package hostile

import (
	"fmt"
	"strconv"
	"strings"
)

// Canary is the synthetic secret-like marker planted in hostile response
// fields. It must never surface in errors or logs (rule O7).
const Canary = "kx-hostile-canary-7f3a9c1e"

// Op is one structure-aware JSON mutation: Code picks the operation, A picks
// the target node (pre-order index modulo node count), B is an operation
// parameter.
type Op struct{ Code, A, B byte }

// Program is a decoded mutation program. The zero Program is the pristine
// control: it changes nothing.
type Program struct {
	Route  int  // route index modulo len(routes)
	Occ    int  // 0 first request only, 1 every request, 2 second request onward
	Status int  // 0 keep, else index into statuses
	CT     int  // 0 keep, else index into contentTypes
	Enc    int  // 0 identity, else index into encodings
	Frame  int  // 0 normal, else index into frames
	Fault  int  // 0 none, else index into faults
	Redir  int  // 0 none, else index into redirects
	Trunc  int  // 0 none, else body kept fraction (Trunc-1)/32 of its length
	Ops    []Op // JSON mutations, applied in order
}

var (
	statuses     = []int{200, 201, 202, 204, 206, 301, 302, 307, 308, 400, 401, 403, 404, 409, 429, 500, 502, 503, 599}
	contentTypes = []string{"", "text/plain", "text/html", "application/xml", "application/octet-stream", "application/json; charset=utf-16", "garbage/\x00x", "application/jsonx"}
	encodings    = []string{"gzip", "gzip-bomb", "gzip-corrupt", "br-label", "gzip-label-raw"}
	frames       = []string{"cl-too-long", "chunked", "cl-too-short", "dup-cl", "chunk-bad-size", "chunk-huge-size", "chunk-unterminated", "te-and-cl", "close-delimited", "chunk-ext-giant", "header-giant", "trailer-giant"}
	faults       = []string{"rst-after-headers", "rst-mid-body", "close-after-headers", "hang", "slow-drip", "garbage", "tls-alert", "accept-close", "partial-headers-hang"}
	redirects    = []string{"attacker-302", "self-loop-307", "same-origin-once-307", "attacker-301-with-body", "other-port-same-host-302"}
)

// threshold keeps each wire-level field "off" for ~87% of random bytes so most
// programs still deliver a body the JSON mutators can act on.
func sel(b byte, n int) int {
	if b < 224 {
		return 0
	}
	return 1 + int(b-224)%n
}

// Decode turns arbitrary bytes into a Program. Every byte string decodes; the
// empty string is pristine. Layout: 9 header bytes, 1 op-count byte, then op
// triples.
func Decode(b []byte) Program {
	at := func(i int) byte {
		if i < len(b) {
			return b[i]
		}
		return 0
	}
	p := Program{
		Route: int(at(0)),
		Occ:   int(at(1)) % 3,
	}
	if s := sel(at(2), len(statuses)); s > 0 {
		p.Status = s
	}
	p.CT = sel(at(3), len(contentTypes))
	p.Enc = sel(at(4), len(encodings))
	p.Frame = sel(at(5), len(frames))
	p.Fault = sel(at(6), len(faults))
	p.Redir = sel(at(7), len(redirects))
	if t := at(8); t >= 224 {
		p.Trunc = 1 + int(t-224)%32
	}
	n := int(at(9)) % 5
	for i := 0; i < n; i++ {
		base := 10 + 3*i
		if base >= len(b) {
			break
		}
		p.Ops = append(p.Ops, Op{at(base), at(base + 1), at(base + 2)})
	}
	return p
}

// Pristine reports whether the program leaves the response untouched.
func (p Program) Pristine() bool {
	return p.Status == 0 && p.CT == 0 && p.Enc == 0 && p.Frame == 0 && p.Fault == 0 && p.Redir == 0 && p.Trunc == 0 && len(p.Ops) == 0
}

// String renders the program for failure messages and reproduction notes.
func (p Program) String() string {
	var s []string
	s = append(s, fmt.Sprintf("route=%d occ=%d", p.Route, p.Occ))
	if p.Status > 0 {
		s = append(s, "status="+strconv.Itoa(statuses[p.Status-1]))
	}
	if p.CT > 0 {
		s = append(s, fmt.Sprintf("ct=%q", contentTypes[p.CT-1]))
	}
	if p.Enc > 0 {
		s = append(s, "enc="+encodings[p.Enc-1])
	}
	if p.Frame > 0 {
		s = append(s, "frame="+frames[p.Frame-1])
	}
	if p.Fault > 0 {
		s = append(s, "fault="+faults[p.Fault-1])
	}
	if p.Redir > 0 {
		s = append(s, "redirect="+redirects[p.Redir-1])
	}
	if p.Trunc > 0 {
		s = append(s, fmt.Sprintf("trunc=%d/32", p.Trunc-1))
	}
	for _, o := range p.Ops {
		s = append(s, fmt.Sprintf("op(%d,%d,%d)", o.Code, o.A, o.B))
	}
	return strings.Join(s, " ")
}

var weirdStrings = []*Node{
	{K: KStr, S: ""},
	{K: KStr, S: " "},
	{K: KStr, S: "null"},
	{K: KRaw, S: "\"a\x00b\""},
	{K: KRaw, S: "\"line1\r\nline2\""},
	{K: KStr, S: "x\r\nX-Injected: 1"},
	{K: KStr, S: "‮​secret‏"},
	{K: KRaw, S: `"\ud800"`},
	{K: KRaw, S: "\"\xff\xfe\xc0\""},
	{K: KStr, S: "\xef\xbb\xbfvalue"},
	{K: KStr, S: "a b c"},
	{K: KStr, S: "../../etc/passwd"},
	{K: KStr, S: "http://127.0.0.1:1/internal"},
	{K: KStr, S: "${jndi:ldap://x}"},
	{K: KStr, S: Canary},
	{K: KStr, S: "a\x00b"},
}

var weirdNums = []string{"1e999", "-0", "9223372036854775808", "-9223372036854775809", "0.1e-400", "NaN", "01", "1.7976931348623157e309", "4294967296", "-1", "0", "1E+2", ".5"}

var hugeSizes = []int{4 << 10, 66 << 10, 1100000, 4300000}
var deepSizes = []int{16, 200, 2000, 20000}
var listSizes = []int{100, 5000, 60000}

func clone(n *Node) *Node {
	if n == nil {
		return nil
	}
	c := &Node{K: n.K, S: n.S}
	c.Keys = append(c.Keys, n.Keys...)
	for _, k := range n.Kids {
		c.Kids = append(c.Kids, clone(k))
	}
	return c
}

// MutateBody applies the program's JSON ops and truncation to a valid body.
// A body that is not JSON passes through the ops untouched (only truncation
// applies).
func (p Program) MutateBody(valid []byte) []byte {
	out := valid
	if len(p.Ops) > 0 {
		if root, err := ParseJSON(valid); err == nil {
			for _, o := range p.Ops {
				applyOp(&root, o)
			}
			out = root.Marshal()
		}
	}
	if p.Trunc > 0 {
		out = out[:len(out)*(p.Trunc-1)/32]
	}
	return out
}

func applyOp(root **Node, o Op) {
	if *root == nil {
		return
	}
	all := (*root).refs()
	r := all[int(o.A)%len(all)]
	n := r.n
	b := int(o.B)
	switch o.Code % 15 {
	case 0: // null
		r.set(root, &Node{K: KNull})
	case 1: // delete
		r.remove(root)
	case 2: // type swap
		switch b % 6 {
		case 0:
			r.set(root, &Node{K: KStr, S: "0"})
		case 1:
			r.set(root, &Node{K: KNum, S: "1"})
		case 2:
			r.set(root, &Node{K: KArr, Kids: []*Node{clone(n)}})
		case 3:
			r.set(root, &Node{K: KObj, Keys: []string{"value"}, Kids: []*Node{clone(n)}})
		case 4:
			r.set(root, &Node{K: KBool, S: "true"})
		case 5:
			r.set(root, &Node{K: KStr, S: string((&Node{K: n.K, S: n.S, Keys: n.Keys, Kids: n.Kids}).Marshal())})
		}
	case 3: // duplicate key with a different value, before or after
		if r.parent != nil && r.parent.K == KObj {
			dup := &Node{K: KNull}
			switch b % 4 {
			case 1:
				dup = &Node{K: KStr, S: ""}
			case 2:
				dup = &Node{K: KObj}
			case 3:
				dup = &Node{K: KStr, S: Canary}
			}
			p := r.parent
			key := p.Keys[r.idx]
			at := r.idx + 1
			if b&0x80 != 0 {
				at = r.idx
			}
			p.Keys = append(p.Keys[:at:at], append([]string{key}, p.Keys[at:]...)...)
			p.Kids = append(p.Kids[:at:at], append([]*Node{dup}, p.Kids[at:]...)...)
		}
	case 4: // huge string
		r.set(root, &Node{K: KStr, S: strings.Repeat("A", hugeSizes[b%len(hugeSizes)])})
	case 5: // deep nesting
		d := deepSizes[b%len(deepSizes)]
		inner := string(n.Marshal())
		open, cls := "[", "]"
		if b&0x80 != 0 {
			open, cls = `{"a":`, "}"
		}
		r.set(root, &Node{K: KRaw, S: strings.Repeat(open, d) + inner + strings.Repeat(cls, d)})
	case 6: // odd string
		w := weirdStrings[b%len(weirdStrings)]
		r.set(root, &Node{K: w.K, S: w.S})
	case 7: // oversized list / object
		cnt := listSizes[b%len(listSizes)]
		switch {
		case n.K == KArr && len(n.Kids) > 0:
			first := n.Kids[0]
			for i := 0; i < cnt; i++ {
				n.Kids = append(n.Kids, clone(first))
			}
		case n.K == KObj:
			for i := 0; i < cnt; i++ {
				n.Keys = append(n.Keys, "k"+strconv.Itoa(i))
				n.Kids = append(n.Kids, &Node{K: KNull})
			}
		default:
			arr := &Node{K: KArr}
			for i := 0; i < cnt; i++ {
				arr.Kids = append(arr.Kids, clone(n))
			}
			r.set(root, arr)
		}
	case 8: // number extremes
		r.set(root, &Node{K: KRaw, S: weirdNums[b%len(weirdNums)]})
	case 9: // key rename
		if r.parent != nil && r.parent.K == KObj {
			k := r.parent.Keys[r.idx]
			switch b % 5 {
			case 0:
				k = strings.ToUpper(k)
			case 1:
				k = " " + k
			case 2:
				k += "\x00"
			case 3:
				k = strings.Replace(k, "a", "а", 1) // Cyrillic homoglyph
			case 4:
				k += "_"
			}
			r.parent.Keys[r.idx] = k
		}
	case 10: // insert extra key into an object
		if n.K == KObj {
			keys := []string{"__proto__", "$ref", Canary, "", "value", "data"}
			n.Keys = append(n.Keys, keys[b%len(keys)])
			n.Kids = append(n.Kids, &Node{K: KStr, S: Canary})
		}
	case 11: // empty container
		switch n.K {
		case KObj:
			r.set(root, &Node{K: KObj})
		case KArr:
			r.set(root, &Node{K: KArr})
		default:
			r.set(root, &Node{K: KStr, S: ""})
		}
	case 12: // canary string
		r.set(root, &Node{K: KStr, S: Canary})
	case 13: // flip bool / negate
		switch n.K {
		case KBool:
			if n.S == "true" {
				n.S = "false"
			} else {
				n.S = "true"
			}
		default:
			r.set(root, &Node{K: KBool, S: "false"})
		}
	case 14: // crossover: copy another subtree here
		src := all[b%len(all)]
		r.set(root, clone(src.n))
	}
}

// Encode is the inverse of Decode for programs built in code (seed corpus).
func Encode(p Program) []byte {
	on := func(idx int) byte {
		if idx <= 0 {
			return 0
		}
		return byte(224 + idx - 1)
	}
	b := []byte{byte(p.Route), byte(p.Occ), on(p.Status), on(p.CT), on(p.Enc), on(p.Frame), on(p.Fault), on(p.Redir), on(p.Trunc), byte(len(p.Ops))}
	for _, o := range p.Ops {
		b = append(b, o.Code, o.A, o.B)
	}
	return b
}
