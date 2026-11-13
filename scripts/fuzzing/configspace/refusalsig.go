package configspace

import (
	"regexp"
	"strings"
)

// The dedupe key of the refusal-unnamed class (I2c) is a MASKED SIGNATURE of the refusal
// text, not the case's option names. The old key was "refusal-unnamed:<first 3 sorted
// param ids>" (firstAssign): in a pair-all row every parameter is assigned, so the first
// three ids are always the same trio regardless of why the config was refused, which
// (1) collapsed unrelated refusals into one key and (2) let minimisation drift from the
// cause it started on to any other refusal that happened to keep the same trio. Keying on
// the masked refusal text instead ties the key to the CAUSE: two different refusals can
// never share a key, and the same refusal with a different line number, path, or quoted
// value keeps its key (so minimisation stays on one cause).
//
// What this does NOT verify: that the masked text is the *minimal* distinguishing
// signature (two genuinely-distinct refusals whose wording differs only in a stripped
// token — a number, a path, a quoted value — would still collapse; that is accepted,
// since such refusals are the "same shape"). It also does not read structured error codes
// (the loader returns plain strings), so the mask is purely lexical.

var (
	// A standard Go log timestamp prefix ("2026/11/13 18:36:47 ").
	reLogStamp = regexp.MustCompile(`\b\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\b`)
	reBacktick = regexp.MustCompile("`[^`]*`")
	reDQuote   = regexp.MustCompile(`"[^"]*"`)
	reSQuote   = regexp.MustCompile(`'[^']*'`)
	// A file path: a run of non-space characters containing at least one slash.
	rePath = regexp.MustCompile(`\S*/\S+`)
	reNum  = regexp.MustCompile(`\d+`)
	// Everything that is not a letter or digit collapses to a single space.
	reNonWord = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// maskRefusal reduces a refusal text to a stable, cause-tied signature by stripping the
// volatile parts: a leading log timestamp, quoted runs (backtick/double/single), file
// paths, and numbers (line numbers, byte sizes, ports, durations). What remains is the
// fixed wording of the error. The result is lower-cased, whitespace-collapsed and capped.
func maskRefusal(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = reLogStamp.ReplaceAllString(s, " ")
	s = reBacktick.ReplaceAllString(s, " ")
	s = reDQuote.ReplaceAllString(s, " ")
	s = reSQuote.ReplaceAllString(s, " ")
	s = rePath.ReplaceAllString(s, " ")
	s = reNum.ReplaceAllString(s, " ")
	s = reNonWord.ReplaceAllString(s, " ")
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// refusalKey builds the dedupe key for an in-process refusal-unnamed finding.
func refusalKey(errText string) string {
	return "refusal-unnamed:" + maskRefusal(errText)
}

// procRefusalKey builds the dedupe key for a process-stage refusal-unnamed finding from
// the server's log. The operative fatal error is the last non-empty line; a YAML
// unmarshal error prints its detail on an indented continuation line, so that one line is
// prefixed with the header line above it.
func procRefusalKey(log string) string {
	return "proc-refusal-unnamed:" + maskRefusal(lastRefusalLine(log))
}

// lastRefusalLine returns the operative refusal line of a process log: the last non-empty
// line, with the preceding line prepended when the last line is an indented continuation
// (the shape a YAML unmarshal error uses: a header line then "  line N: ...").
func lastRefusalLine(log string) string {
	lines := strings.Split(log, "\n")
	i := len(lines) - 1
	for i >= 0 && strings.TrimSpace(lines[i]) == "" {
		i--
	}
	if i < 0 {
		return ""
	}
	last := strings.TrimSpace(lines[i])
	if i > 0 && (strings.HasPrefix(lines[i], " ") || strings.HasPrefix(lines[i], "\t")) {
		return strings.TrimSpace(lines[i-1]) + " " + last
	}
	return last
}
