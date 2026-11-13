package grammar

import (
	"sort"
	"strings"
)

// XMLItem is one child of an element: another element, a text run, a comment, or
// a CDATA section. Exactly one of the pointers/fields is meaningful, selected by
// Kind.
type XMLItem struct {
	Kind XMLKind
	Elem *XMLNode // Kind==XMLElem
	Text string   // Kind==XMLText / XMLComment / XMLCData (raw, un-escaped payload)
}

// XMLKind selects which member of XMLItem is live.
type XMLKind uint8

const (
	XMLElem XMLKind = iota
	XMLText
	XMLComment
	XMLCData
)

// XMLAttr is one attribute. Name is the raw qualified name (may carry a prefix);
// Value is the raw, un-escaped value.
type XMLAttr struct {
	Name  string
	Value string
}

// XMLNS is one namespace declaration (xmlns:Prefix="URI", or default xmlns when
// Prefix=="").
type XMLNS struct {
	Prefix string
	URI    string
}

// XMLNode is one element. The mutation set lives in XMLMut on the document (some
// mutations are per-element and recorded here instead).
type XMLNode struct {
	Prefix   string
	Local    string
	NS       []XMLNS
	Attrs    []XMLAttr
	Children []XMLItem

	// ReorderAttrs, when set, sorts this element's attributes by name before
	// serialising — the "attribute reorder" mutation, benign to a conformant
	// parser but a canonicalisation / signature-surface perturbation.
	ReorderAttrs bool
	// DupID, when non-empty, emits a second id="DupID" attribute in addition to
	// any existing one — the "duplicate ID" malformation (two elements, or one
	// element twice, claiming the same ID).
	DupID string
}

// XMLDoc is a whole document: an optional XML declaration, an optional DOCTYPE /
// internal entity subset, a root element, and document-level mutation flags.
type XMLDoc struct {
	Decl    bool    // emit <?xml version="1.0"?>
	Doctype Doctype // optional DOCTYPE
	Root    *XMLNode
	Mut     XMLMut
}

// Doctype describes an optional DOCTYPE declaration with an internal subset of
// entity definitions. Entities is a list of (name, value) internal general
// entities; if any value references another entity, a lax parser may expand
// recursively (the billion-laughs shape — reportable, never expanded here by the
// builder itself).
type Doctype struct {
	Name     string
	RootName string
	Entities []XMLEntity
}

// XMLEntity is one internal general entity definition.
type XMLEntity struct {
	Name  string
	Value string
}

// XMLMut is the document-level mutation set.
type XMLMut struct {
	// RebindPrefix, when set, rewrites every element's namespace prefix to
	// RebindTo without moving the corresponding xmlns declaration — so a prefix
	// resolves to a different (or no) URI than the tag's author intended, the
	// "namespace prefix rebinding" confusion.
	RebindPrefix bool
	RebindTo     string
	// ExtraWhitespace injects runs of insignificant whitespace between elements.
	ExtraWhitespace bool
	// SplitText, when set, breaks each text run into two adjacent CDATA sections
	// / text nodes around its midpoint (comment/CDATA splitting) so a consumer
	// that treats adjacent text as one logical value is exercised.
	SplitText bool
}

// Build serialises the document to a string.
func (d *XMLDoc) Build() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	if d.Decl {
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	}
	if d.Doctype.Name != "" || len(d.Doctype.Entities) > 0 {
		b.WriteString(buildDoctype(d.Doctype))
	}
	if d.Root != nil {
		writeElem(&b, d.Root, &d.Mut)
	}
	return b.String()
}

// BuildFragment serialises just the root element (no declaration / DOCTYPE) — the
// form the SAML transitive target needs, where a fragment is spliced into a
// larger signed envelope.
func (d *XMLDoc) BuildFragment() string {
	if d == nil || d.Root == nil {
		return ""
	}
	var b strings.Builder
	mut := XMLMut{}
	if d != nil {
		mut = d.Mut
	}
	writeElem(&b, d.Root, &mut)
	return b.String()
}

func buildDoctype(dt Doctype) string {
	name := dt.RootName
	if name == "" {
		name = "r"
	}
	if len(dt.Entities) == 0 {
		return "<!DOCTYPE " + name + ">"
	}
	var b strings.Builder
	b.WriteString("<!DOCTYPE ")
	b.WriteString(name)
	b.WriteString(" [")
	for _, e := range dt.Entities {
		b.WriteString(`<!ENTITY `)
		b.WriteString(e.Name)
		b.WriteString(` "`)
		b.WriteString(e.Value)
		b.WriteString(`">`)
	}
	b.WriteString("]>")
	return b.String()
}

func writeElem(b *strings.Builder, n *XMLNode, mut *XMLMut) {
	if n == nil {
		return
	}
	prefix := n.Prefix
	if mut != nil && mut.RebindPrefix && prefix != "" {
		prefix = mut.RebindTo
	}
	qname := n.Local
	if qname == "" {
		qname = "e"
	}
	if prefix != "" {
		qname = prefix + ":" + qname
	}

	b.WriteByte('<')
	b.WriteString(qname)
	for _, ns := range n.NS {
		if ns.Prefix == "" {
			b.WriteString(` xmlns="`)
		} else {
			b.WriteString(` xmlns:`)
			b.WriteString(ns.Prefix)
			b.WriteString(`="`)
		}
		b.WriteString(escapeAttr(ns.URI))
		b.WriteByte('"')
	}

	attrs := n.Attrs
	if n.ReorderAttrs {
		attrs = append([]XMLAttr(nil), attrs...)
		sort.SliceStable(attrs, func(i, j int) bool { return attrs[i].Name < attrs[j].Name })
	}
	for _, a := range attrs {
		b.WriteByte(' ')
		b.WriteString(a.Name)
		b.WriteString(`="`)
		b.WriteString(escapeAttr(a.Value))
		b.WriteByte('"')
	}
	if n.DupID != "" {
		b.WriteString(` id="`)
		b.WriteString(escapeAttr(n.DupID))
		b.WriteByte('"')
	}

	if len(n.Children) == 0 {
		b.WriteString("/>")
		return
	}
	b.WriteByte('>')
	for _, c := range n.Children {
		if mut != nil && mut.ExtraWhitespace {
			b.WriteString("  \n")
		}
		writeItem(b, c, mut)
	}
	b.WriteString("</")
	b.WriteString(qname)
	b.WriteByte('>')
}

func writeItem(b *strings.Builder, it XMLItem, mut *XMLMut) {
	switch it.Kind {
	case XMLElem:
		writeElem(b, it.Elem, mut)
	case XMLText:
		if mut != nil && mut.SplitText && len(it.Text) > 1 {
			mid := len(it.Text) / 2
			b.WriteString(escapeText(it.Text[:mid]))
			b.WriteString(escapeText(it.Text[mid:]))
			return
		}
		b.WriteString(escapeText(it.Text))
	case XMLComment:
		b.WriteString("<!--")
		b.WriteString(stripCommentUnsafe(it.Text))
		b.WriteString("-->")
	case XMLCData:
		if mut != nil && mut.SplitText && len(it.Text) > 1 {
			mid := len(it.Text) / 2
			writeCData(b, it.Text[:mid])
			writeCData(b, it.Text[mid:])
			return
		}
		writeCData(b, it.Text)
	}
}

func writeCData(b *strings.Builder, s string) {
	b.WriteString("<![CDATA[")
	// A CDATA section cannot contain the literal "]]>"; split it if present so
	// the builder always emits well-formed CDATA framing. Control characters are
	// dropped (illegal in XML char data even inside CDATA).
	b.WriteString(strings.ReplaceAll(sanitizeXMLChars(s), "]]>", "]]]]><![CDATA[>"))
	b.WriteString("]]>")
}

// stripCommentUnsafe removes the only sequences that cannot appear inside an XML
// comment ("--" and a trailing "-"), keeping the builder's output well-formed
// regardless of fuzzer-chosen text.
func stripCommentUnsafe(s string) string {
	s = sanitizeXMLChars(s)
	s = strings.ReplaceAll(s, "--", "- ")
	s = strings.TrimRight(s, "-")
	return s
}

func escapeAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(sanitizeXMLChars(s))
}

func escapeText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(sanitizeXMLChars(s))
}

// sanitizeXMLChars drops bytes/runes that are illegal in XML 1.0 character data
// (control characters other than tab/newline/CR, and invalid UTF-8), so the
// builder's framing stays well-formed no matter what arbitrary bytes the fuzzer
// chose for a text/attribute payload. The structural mutations — not the payload
// bytes — are what this grammar explores, so filtering the payload loses nothing.
func sanitizeXMLChars(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(r)
		case r >= 0x20 && r != 0xFFFD && r <= 0xD7FF:
			b.WriteRune(r)
		case r >= 0xE000 && r <= 0x10FFFF && r != 0xFFFE && r != 0xFFFF:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Depth returns the maximum element nesting depth (a leaf element is depth 1).
func (n *XMLNode) Depth() int {
	if n == nil {
		return 0
	}
	max := 0
	for _, c := range n.Children {
		if c.Kind == XMLElem {
			if d := c.Elem.Depth(); d > max {
				max = d
			}
		}
	}
	return max + 1
}
