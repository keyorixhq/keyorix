package hostile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Kind is a JSON node kind. KRaw holds verbatim text emitted as-is, which lets
// a mutation produce bytes encoding/json would never emit (raw NUL or CRLF
// inside a string, lone surrogate escapes, invalid UTF-8, NaN, ...).
type Kind uint8

// JSON node kinds.
const (
	KNull Kind = iota
	KBool
	KNum
	KStr
	KArr
	KObj
	KRaw
)

// Node is an order-preserving JSON tree node that, unlike a Go map, can hold
// duplicate object keys.
type Node struct {
	K    Kind
	S    string   // KBool "true"/"false"; KNum literal; KStr decoded text; KRaw verbatim
	Keys []string // KObj only, parallel to Kids
	Kids []*Node
}

// ParseJSON parses b into a Node tree. Duplicate keys are preserved.
func ParseJSON(b []byte) (*Node, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	n, err := parseVal(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	return n, nil
}

func parseVal(dec *json.Decoder) (*Node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		if v == '[' {
			n := &Node{K: KArr}
			for dec.More() {
				c, err := parseVal(dec)
				if err != nil {
					return nil, err
				}
				n.Kids = append(n.Kids, c)
			}
			_, err := dec.Token()
			return n, err
		}
		n := &Node{K: KObj}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			c, err := parseVal(dec)
			if err != nil {
				return nil, err
			}
			n.Keys = append(n.Keys, kt.(string))
			n.Kids = append(n.Kids, c)
		}
		_, err := dec.Token()
		return n, err
	case string:
		return &Node{K: KStr, S: v}, nil
	case json.Number:
		return &Node{K: KNum, S: string(v)}, nil
	case bool:
		if v {
			return &Node{K: KBool, S: "true"}, nil
		}
		return &Node{K: KBool, S: "false"}, nil
	default:
		return &Node{K: KNull}, nil
	}
}

// Marshal serialises the tree. A nil tree yields an empty body.
func (n *Node) Marshal() []byte {
	if n == nil {
		return nil
	}
	var b bytes.Buffer
	n.write(&b)
	return b.Bytes()
}

func (n *Node) write(b *bytes.Buffer) {
	switch n.K {
	case KNull:
		b.WriteString("null")
	case KBool, KNum, KRaw:
		b.WriteString(n.S)
	case KStr:
		enc, _ := json.Marshal(n.S)
		b.Write(enc)
	case KArr:
		b.WriteByte('[')
		for i, c := range n.Kids {
			if i > 0 {
				b.WriteByte(',')
			}
			c.write(b)
		}
		b.WriteByte(']')
	case KObj:
		b.WriteByte('{')
		for i, c := range n.Kids {
			if i > 0 {
				b.WriteByte(',')
			}
			enc, _ := json.Marshal(n.Keys[i])
			b.Write(enc)
			b.WriteByte(':')
			c.write(b)
		}
		b.WriteByte('}')
	}
}

// ref locates a node: parent==nil means the root.
type ref struct {
	parent *Node
	idx    int
	n      *Node
}

// refs returns every node in pre-order.
func (n *Node) refs() []ref {
	out := []ref{{nil, 0, n}}
	var walk func(p *Node)
	walk = func(p *Node) {
		for i, c := range p.Kids {
			out = append(out, ref{p, i, c})
			walk(c)
		}
	}
	walk(n)
	return out
}

// set replaces the referenced node (the root pointer is updated via root).
func (r ref) set(root **Node, repl *Node) {
	if r.parent == nil {
		*root = repl
		return
	}
	r.parent.Kids[r.idx] = repl
}

// remove deletes the referenced node from its parent (root removal yields nil).
func (r ref) remove(root **Node) {
	if r.parent == nil {
		*root = nil
		return
	}
	p := r.parent
	p.Kids = append(p.Kids[:r.idx:r.idx], p.Kids[r.idx+1:]...)
	if p.K == KObj {
		p.Keys = append(p.Keys[:r.idx:r.idx], p.Keys[r.idx+1:]...)
	}
}

// HasDuplicateKeys reports whether any JSON object in b repeats a member name.
// RFC 8259 leaves the meaning of such an object undefined ("behavior of
// software that receives such an object is unpredictable"), so strict decoders
// in targets treat a body with duplicates as having no single correct reading
// and skip value-level assertions on it (delivery and bounded-work oracles
// still apply). Unparseable input reports false.
func HasDuplicateKeys(b []byte) bool {
	root, err := ParseJSON(b)
	if err != nil {
		return false
	}
	var walk func(n *Node) bool
	walk = func(n *Node) bool {
		if n.K == KObj {
			seen := make(map[string]struct{}, len(n.Keys))
			for _, k := range n.Keys {
				if _, dup := seen[k]; dup {
					return true
				}
				seen[k] = struct{}{}
			}
		}
		for _, c := range n.Kids {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(root)
}
