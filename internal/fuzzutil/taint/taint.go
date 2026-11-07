// Package taint is an input-to-sink taint oracle for Go fuzz harnesses.
//
// The harness embeds a fixed high-entropy marker in the strings it feeds to the
// code under test (taint.Str, taint.Bytes, or taint.Marker directly). The
// standard library, patched by `go build -overlay` (see cmd/taintoverlay), calls
// a hook at every dangerous sink: file paths, exec commands/args/env, network
// hosts, database/sql query text, template text, log output. The hook reports a
// violation when the sink argument contains the marker or a common encoding of
// it. A harness then fails the fuzz iteration with taint.Check(t.Fatalf).
//
// The hook is a nil-checked function variable in the standard library, so the
// cost with no marker in play is one load and compare per sink call; the
// substring scan runs only when a hook is installed, and the stack walk only on
// a match.
//
// Binaries built without `-tags taintoverlay -overlay=...` compile and run, but
// see no sinks; Enabled() reports false and RequireOverlay fails the test so a
// harness cannot pass silently with the oracle off.
//
// Expected flows are declared with Expect (scoped to one call) or Allow (rules
// matched on class, sink op and a stack frame substring). Allowed flows are
// kept and reported separately, never dropped silently.
package taint

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Class is the kind of dangerous sink a marker reached.
type Class string

const (
	Path     Class = "path"
	Host     Class = "host"
	Command  Class = "command"
	Query    Class = "query"
	Template Class = "template"
	Log      Class = "log"
	// URLTail: the marker is in the path/query of a URL, not its host.
	URLTail Class = "urltail"
)

// DefaultMarker is 12 lowercase alphanumeric bytes, chosen at random once. It is
// lowercase because DNS and some parsers lowercase their input.
const DefaultMarker = "qz7kx4m9vtw2"

// Violation is one marker-to-sink flow.
type Violation struct {
	Class  Class
	Op     string // sink function, e.g. "os.OpenFile"
	Form   string // which encoding of the marker matched
	Value  string // the sink argument, truncated
	Stack  []string
	Reason string // set for allowed flows
}

func (v Violation) String() string {
	return fmt.Sprintf("%s via %s (marker form %s) value=%q\n    %s", v.Class, v.Op, v.Form, v.Value, strings.Join(v.Stack, "\n    "))
}

// Rule allows a class of flow. Empty fields match anything. Op is a path.Match
// glob on the sink op; Frame is a substring of any frame's function name.
type Rule struct {
	Class Class
	Op    string
	Frame string
	// Root, for Path flows, allows the flow when the cleaned absolute path lies
	// strictly inside this directory (a confined flow); Root may contain glob
	// elements, e.g. "/tmp/h/dsd-raw-*". A path that escapes it,
	// e.g. via "../" or an absolute marker path, stays unexpected.
	Root string
	// Func, when set, must return true for the rule to match (full control for
	// contracts the fields above cannot express).
	Func func(Violation) bool
	Why  string
}

type needle struct{ form, s string }

var (
	mu       sync.Mutex
	marker   = DefaultMarker
	needles  = buildNeedles(DefaultMarker)
	rules    []Rule
	expect   = map[Class]int{}
	expectBy = map[Class]string{}
	viol     []Violation
	allowed  []Violation
	seen     = map[string]bool{}
	fatal    = map[Class]bool{Path: true, Host: true, Command: true, Query: true, Template: true}
	checked  atomic.Uint64
	hits     atomic.Uint64
)

// Marker returns the current marker.
func Marker() string { return marker }

// SetMarker replaces the marker (at least 8 bytes, lowercase alphanumeric
// recommended). Call before fuzzing starts.
func SetMarker(m string) {
	if len(m) < 8 {
		panic("taint: marker must be at least 8 bytes")
	}
	mu.Lock()
	marker = m
	ns := buildNeedles(m)
	needlesP.Store(&ns)
	mu.Unlock()
}

// SetFatal chooses which classes make Check fail. Others are only recorded.
func SetFatal(cs ...Class) {
	mu.Lock()
	fatal = map[Class]bool{}
	for _, c := range cs {
		fatal[c] = true
	}
	mu.Unlock()
}

func buildNeedles(m string) []needle {
	var ns []needle
	add := func(form, s string) {
		if len(s) >= 6 {
			ns = append(ns, needle{form, s})
		}
	}
	add("raw-prefix", m[:8])
	add("raw-suffix", m[len(m)-8:])
	add("upper", strings.ToUpper(m))
	add("hex", hex.EncodeToString([]byte(m)))
	add("HEX", strings.ToUpper(hex.EncodeToString([]byte(m))))
	// base64 at the three possible alignments; keep only characters fully
	// determined by the marker bytes.
	for k := 0; k < 3; k++ {
		for _, e := range []struct {
			n   string
			enc *base64.Encoding
		}{{"b64", base64.StdEncoding}, {"b64url", base64.URLEncoding}} {
			s := e.enc.EncodeToString(append(make([]byte, k), m...))
			start := (k*8 + 5) / 6
			end := (k + len(m)) * 8 / 6
			if end > start {
				add(fmt.Sprintf("%s+%d", e.n, k), s[start:end])
			}
		}
	}
	return ns
}

// Enabled reports whether this binary was built with the sink hooks.
func Enabled() bool { return overlayActive }

// RequireOverlay fails the test when the oracle is not active.
func RequireOverlay(fatalf func(string, ...any)) {
	if !overlayActive {
		fatalf("taint oracle inactive: build with `-tags taintoverlay -overlay=<dir>/overlay.json` (see taint/taintgo)")
	}
}

// Reset clears recorded flows and scoped expectations. Call at the start of
// every fuzz iteration.
func Reset() {
	mu.Lock()
	viol, allowed = nil, nil
	seen = map[string]bool{}
	mu.Unlock()
}

// Allow installs global rules for expected flows.
func Allow(rs ...Rule) {
	mu.Lock()
	rules = append(rules, rs...)
	mu.Unlock()
}

// ResetRules removes all rules installed with Allow.
func ResetRules() {
	mu.Lock()
	rules = nil
	mu.Unlock()
}

// Expect declares that flows of a class are expected until the returned func is
// called, e.g. a library that legitimately opens the path you handed it:
//
//	defer taint.Expect(taint.Path, "LoadFile opens its argument")()
func Expect(c Class, why string) (done func()) {
	mu.Lock()
	expect[c]++
	expectBy[c] = why
	mu.Unlock()
	return func() {
		mu.Lock()
		expect[c]--
		mu.Unlock()
	}
}

var classKind = map[Class]int{Path: 1, Host: 2, Command: 3, Query: 4, Template: 5, Log: 6}

// Sink reports a flow at a harness-defined boundary (a fake Source, Executor or
// HTTP client interface) exactly as the stdlib hooks do. It works without the
// overlay. Use it when the real sink is replaced by a test double.
func Sink(c Class, op, s string) {
	k, ok := classKind[c]
	if !ok {
		k = 1
	}
	hook(k, op, s)
}

// Stats returns the number of sink calls inspected and marker hits so far.
func Stats() (inspected, hit uint64) { return checked.Load(), hits.Load() }

// Flows returns the unexpected and the allowed flows recorded since Reset.
func Flows() (unexpected, allowedFlows []Violation) {
	mu.Lock()
	defer mu.Unlock()
	return append([]Violation(nil), viol...), append([]Violation(nil), allowed...)
}

// Check fails the iteration (via fatalf, pass t.Fatalf) if an unexpected flow of
// a fatal class was recorded since Reset. Non-fatal classes stay in Flows().
func Check(fatalf func(format string, args ...any)) {
	mu.Lock()
	var bad []Violation
	for _, v := range viol {
		if fatal[v.Class] {
			bad = append(bad, v)
		}
	}
	mu.Unlock()
	if len(bad) == 0 {
		return
	}
	var b strings.Builder
	for _, v := range bad {
		b.WriteString("\n  ")
		b.WriteString(v.String())
	}
	fatalf("TAINT: fuzz input reached %d sink(s):%s", len(bad), b.String())
}

// Str returns a marker-bearing string derived from s. The position of the
// marker (alone, before, after, inside s) is chosen from s itself so the
// fuzzer can steer it.
func Str(s string) string {
	switch len(s) % 4 {
	case 0:
		return marker
	case 1:
		return marker + s
	case 2:
		return s + marker
	}
	h := len(s) / 2
	return s[:h] + marker + s[h:]
}

// PathStr is Str for values used as file paths: besides the plain positions it
// produces "../", "../../" and absolute ("/"+marker) forms so that a sink that is
// only meant to see a path under a base directory can be caught escaping it
// (pair with Rule{Root: base}).
func PathStr(s string) string {
	switch len(s) % 6 {
	case 0:
		return marker
	case 1:
		return "../" + marker
	case 2:
		return "/" + marker
	case 3:
		return "../../" + marker + "/x"
	case 4:
		return s + "/" + marker
	}
	return marker + "/../../" + s
}

// Bytes is Str for byte slices.
func Bytes(b []byte) []byte { return []byte(Str(string(b))) }

// hook is installed by hook_overlay.go.
func hook(kind int, op, s string) {
	checked.Add(1)
	if len(s) < 6 {
		return
	}
	ns := *needlesP.Load()
	form := ""
	for _, n := range ns {
		if strings.Contains(s, n.s) {
			form = n.form
			break
		}
	}
	if form == "" {
		return
	}
	hits.Add(1)
	record(kind, op, s, form)
}

var kindClass = map[int]Class{1: Path, 2: Host, 3: Command, 4: Query, 5: Template, 6: Log}

func record(kind int, op, s, form string) {
	cls := kindClass[kind]
	if kind == 7 { // URL: only the authority is a host flow
		cls = URLTail
		if u, err := url.Parse(s); err == nil && containsAny(u.Host+u.User.String(), needlesNow()) {
			cls = Host
		}
	}
	pcs := make([]uintptr, 48)
	pcs = pcs[:runtime.Callers(3, pcs)]
	pk := fmt.Sprint(cls, op, pcs[:min(len(pcs), 8)])
	mu.Lock()
	dup := seen[pk]
	seen[pk] = true
	mu.Unlock()
	if dup {
		return
	}
	frames := symbolize(pcs)
	// exec.LookPath stats candidate paths for a command name: that is the
	// command flow, already reported by exec.Command.
	for _, f := range frames {
		if strings.Contains(f, "os/exec.LookPath") || strings.Contains(f, "os/exec.findExecutable") || strings.Contains(f, "os/exec.lookExtensions") {
			return
		}
	}
	v := Violation{Class: cls, Op: op, Form: form, Value: trunc(s, 160), Stack: userFrames(frames)}
	mu.Lock()
	defer mu.Unlock()
	if expect[cls] > 0 {
		v.Reason = "Expect: " + expectBy[cls]
		allowed = append(allowed, v)
		return
	}
	for _, r := range rules {
		if r.Class != "" && r.Class != cls {
			continue
		}
		if r.Op != "" {
			if ok, _ := path.Match(r.Op, op); !ok {
				continue
			}
		}
		if r.Frame != "" && !anyContains(frames, r.Frame) {
			continue
		}
		if r.Root != "" && (cls != Path || !under(s, r.Root)) {
			continue
		}
		if r.Func != nil && !r.Func(v) {
			continue
		}
		v.Reason = "Allow: " + r.Why
		allowed = append(allowed, v)
		return
	}
	viol = append(viol, v)
}

func needlesNow() []needle { return *needlesP.Load() }

var needlesP atomic.Pointer[[]needle]

func init() { needlesP.Store(&needles) }

func containsAny(s string, ns []needle) bool {
	for _, n := range ns {
		if strings.Contains(s, n.s) {
			return true
		}
	}
	return false
}

func anyContains(fs []string, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// symbolize returns "func file:line" for the whole stack.
func symbolize(pcs []uintptr) []string {
	fr := runtime.CallersFrames(pcs)
	var out []string
	for {
		f, more := fr.Next()
		out = append(out, fmt.Sprintf("%s %s:%d", f.Function, shortFile(f.File), f.Line))
		if !more {
			break
		}
	}
	return out
}

// userFrames keeps up to 8 frames that are not stdlib/runtime/testing plumbing.
func userFrames(fs []string) []string {
	var out []string
	for _, f := range fs {
		fn := f[:strings.IndexByte(f, ' ')]
		if isStd(fn) || strings.Contains(fn, "/taint.") || strings.HasPrefix(fn, "taint.") || strings.HasPrefix(fn, "testing.") {
			continue
		}
		out = append(out, f)
		if len(out) == 8 {
			break
		}
	}
	if len(out) == 0 { // everything was std: keep the top three for context
		out = fs[:min(3, len(fs))]
	}
	return out
}

func isStd(fn string) bool {
	first := fn
	if i := strings.IndexAny(fn, "/."); i >= 0 {
		first = fn[:i]
	}
	// std packages have no dot in the first path element
	if i := strings.IndexByte(fn, '/'); i >= 0 {
		return !strings.Contains(fn[:i], ".") && std[first]
	}
	return std[first]
}

var std = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields("runtime os io bufio bytes strings strconv fmt errors sort sync syscall time context net database log text html encoding path reflect unsafe internal crypto compress archive mime unicode regexp math slices maps iter testing") {
		m[s] = true
	}
	return m
}()

func shortFile(f string) string {
	if i := strings.LastIndex(f, "/"); i >= 0 {
		if j := strings.LastIndex(f[:i], "/"); j >= 0 {
			return f[j+1:]
		}
	}
	return f
}

// Summary lists classes of the given flows, e.g. "path:2 host:1".
func Summary(vs []Violation) string {
	c := map[Class]int{}
	for _, v := range vs {
		c[v.Class]++
	}
	var ks []string
	for k, n := range c {
		ks = append(ks, fmt.Sprintf("%s:%d", k, n))
	}
	sort.Strings(ks)
	return strings.Join(ks, " ")
}

// rootVariants returns root and its symlink-resolved form.
func under(p, root string) bool {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return false
		}
		p = filepath.Join(wd, p)
	}
	p = filepath.Clean(p)
	if strings.ContainsAny(root, "*?[") { // glob root, e.g. /tmp/x/dsd-raw-*
		root = filepath.Clean(root)
		n := strings.Count(root, string(filepath.Separator))
		el := strings.Split(p, string(filepath.Separator))
		if len(el) <= n+1 {
			return false
		}
		ok, _ := filepath.Match(root, strings.Join(el[:n+1], string(filepath.Separator)))
		return ok
	}
	for _, r := range rootVariants(root) {
		if strings.HasPrefix(p, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func rootVariants(root string) []string {
	root = filepath.Clean(root)
	out := []string{root}
	if r, err := filepath.EvalSymlinks(root); err == nil && r != root {
		out = append(out, r)
	}
	return out
}
