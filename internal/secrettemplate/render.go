// Package secrettemplate renders templates that embed Keyorix secret references,
// expanding ${secret:<ref>} placeholders to their values. It is the pure, transport-
// and storage-agnostic core: the caller supplies a Resolver that maps a reference to
// a value (with its own permission checks). Rendered output is never logged by this
// package.
package secrettemplate

import (
	"fmt"
	"strings"
)

// marker is the placeholder prefix; a reference looks like ${secret:<ref>}.
const marker = "${secret:"

// Resolver maps a secret reference (the text between "${secret:" and "}") to its
// value. It returns an error when the reference is unknown or inaccessible.
type Resolver func(ref string) (string, error)

// Render expands every ${secret:<ref>} placeholder in tmpl using resolve and returns
// the result. Rules:
//   - "$$" collapses to a literal "$" — so "$${secret:x}" renders the literal text
//     "${secret:x}" without resolving anything.
//   - a "$" not part of "$$" or a placeholder is literal.
//   - an unterminated placeholder (no closing "}") or an empty ref is an error.
//   - a resolver error aborts the render, naming the offending reference.
//
// References are collected in order; resolve is called once per occurrence.
func Render(tmpl string, resolve Resolver) (string, error) {
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		c := tmpl[i]
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		// c == '$'
		if i+1 < len(tmpl) && tmpl[i+1] == '$' {
			b.WriteByte('$') // "$$" -> "$"
			i += 2
			continue
		}
		if strings.HasPrefix(tmpl[i:], marker) {
			rest := tmpl[i+len(marker):]
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${secret:…} placeholder at offset %d", i)
			}
			ref := strings.TrimSpace(rest[:end])
			if ref == "" {
				return "", fmt.Errorf("empty secret reference at offset %d", i)
			}
			val, err := resolve(ref)
			if err != nil {
				return "", fmt.Errorf("resolve %q: %w", ref, err)
			}
			b.WriteString(val)
			i += len(marker) + end + 1 // past the closing '}'
			continue
		}
		// A lone '$' that doesn't start a placeholder.
		b.WriteByte('$')
		i++
	}
	return b.String(), nil
}

// References returns the distinct secret references in tmpl, in first-seen order,
// without resolving them — useful for a dry-run / "what does this template need?"
// preflight. Malformed placeholders are reported as an error, matching Render.
func References(tmpl string) ([]string, error) {
	var refs []string
	seen := map[string]bool{}
	_, err := Render(tmpl, func(ref string) (string, error) {
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
		return "", nil
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}
