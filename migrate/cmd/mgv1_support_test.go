package cmd

// MGV1 shared test support for the Vault→Keyorix migration-fidelity oracles
// (FuzzVaultImportRoundTrip, FuzzVaultImportConvergence).
//
// This file holds, with NO assertions of its own:
//   - a deterministic fuzz byte-reader (reader),
//   - a generated Vault KV v1/v2 export model (vModel/vLeaf/vField) plus a faithful
//     httptest Vault server that serves it over the exact wire protocol
//     vaultsource.Client speaks (sys/internal/ui/mounts, metadata LIST, data/plain READ),
//   - an in-memory fake target.API (fakeStore) that mirrors the real Keyorix HTTP
//     client's OBSERVABLE semantics: per-(project/env) name uniqueness, atomic
//     create-with-metadata, lookup/metadata/value reads — with an optional per-write
//     fault schedule for the partial-failure oracle.
//
// The oracles themselves live in mgv1_roundtrip_fuzz_test.go and
// mgv1_convergence_fuzz_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
)

// Enforce GOMAXPROCS=2 in the test binary AND in every `go test -fuzz` worker process
// (same binary) — the session permission layer auto-denies any env-prefix/`nice` wrapper,
// so the only way to honour the "GOMAXPROCS=2" resource rule is from inside the process.
func init() {
	runtime.GOMAXPROCS(2)
	// Special runes added from code points (kept out of the source literal: a BOM in source
	// is a compile error). U+202E bidi override, U+200B zero-width space, U+0085 NEL,
	// U+FEFF BOM, U+0007 bell (control), U+2028 line separator.
	for _, cp := range []rune{0x202e, 0x200b, 0x0085, 0xfeff, 0x0007, 0x2028} {
		hostileFrags = append(hostileFrags, string(cp))
	}
}

// ---------------------------------------------------------------------------
// fuzz byte-reader
// ---------------------------------------------------------------------------

type reader struct {
	b []byte
	i int
}

func (r *reader) u8() int {
	if r.i >= len(r.b) {
		return 0
	}
	v := int(r.b[r.i])
	r.i++
	return v
}

// intn returns a value in [0,n). n<=0 yields 0.
func (r *reader) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return r.u8() % n
}

func (r *reader) more() bool { return r.i < len(r.b) }

// ---------------------------------------------------------------------------
// hostile content palette — bytes/runes a real customer Vault can carry in a
// key, a path segment, or a value, and that must never crash, escape the target
// namespace, or leak.
// ---------------------------------------------------------------------------

var hostileFrags = []string{
	"../", "..", "/", "\\", "\x00", "\x01\x02", "\r\n", "\n", "\t",
	"café", "日本語", "\U0001f600", "  ", "--", ":", "#",
	"CON", "NUL", "..\\..\\", "%2e%2e", "{", "}", "[", "]", "\"", "'",
	"a", "b", "x", "key", "value", "db-password", "team",
	strings.Repeat("L", 300), // very long component
}

// frag returns a hostile fragment chosen by the reader.
func (r *reader) frag() string { return hostileFrags[r.intn(len(hostileFrags))] }

// name builds a 1..3-fragment string (a path segment, field key, or value core).
func (r *reader) name() string {
	n := 1 + r.intn(3)
	var sb strings.Builder
	for range n {
		sb.WriteString(r.frag())
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Vault KV export model
// ---------------------------------------------------------------------------

type vField struct {
	key string
	val string // always a JSON-string-typed field; non-string KV values are not generated
}

type vLeaf struct {
	segs   []string // path segments relative to the mount (>=1)
	fields []vField // rendered as a JSON object in order (duplicate keys possible)
	// state: 0=live, 1=soft-deleted (v2), 2=destroyed (v2), 3=empty-leaf (data {}),
	// 4=absent (404). For v1 only 0/3/4 are meaningful.
	state   int
	version int               // v2 version (>=1 when live)
	created string            // v2 created_time
	custom  map[string]string // v2 custom_metadata
}

type vModel struct {
	mount  string
	kv2    bool
	leaves []vLeaf
	byPath map[string]*vLeaf // "a/b" -> leaf
	valTag int               // monotonic unique-value counter
}

// path returns the leaf path relative to mount, e.g. "team-a/db".
func (l *vLeaf) path() string { return strings.Join(l.segs, "/") }

// uniqueVal returns a globally-unique value string carrying a prefix tag and hostile core.
func (m *vModel) uniqueVal(prefix, core string) string {
	m.valTag++
	return fmt.Sprintf("%s%d§%s", prefix, m.valTag, core)
}

// genModel decodes a Vault KV export shape from the fuzz bytes. Depth is capped well below
// vaultsource.maxWalkDepth so a legal tree never trips the depth guard (that guard is tested
// by TestWalk_DepthCapped). Values are kept small to stay off the value-too-large branch.
func genModel(r *reader) *vModel {
	m := &vModel{byPath: map[string]*vLeaf{}}
	m.kv2 = r.intn(2) == 0
	// Mount name: sometimes odd, but keep it URL-safe-ish; the mount is not the
	// security-critical surface (the secret NAME derives from path/field).
	switch r.intn(3) {
	case 0:
		m.mount = "secret"
	case 1:
		m.mount = "kv-" + sanitizeLite(r.frag())
	default:
		m.mount = "m" + fmt.Sprint(r.intn(99))
	}
	if m.mount == "" {
		m.mount = "secret"
	}

	nLeaves := 1 + r.intn(10)
	used := map[string]bool{}
	for range nLeaves {
		if !r.more() {
			break
		}
		depth := 1 + r.intn(3)
		segs := make([]string, 0, depth)
		for range depth {
			seg := r.name()
			// Path segments must stay ROUTABLE through the fake Vault's URL handler: a "/",
			// a NUL, or a "."/".." traversal token would be rewritten by net/http path
			// cleaning and mis-route, breaking the walk for reasons unrelated to import
			// fidelity. The hostile palette (../, NUL, bidi, control, long) is instead carried
			// by the FIELD KEYS below, which flow into sanitizeSecretName without touching
			// routing — that is where name-derivation safety is actually tested.
			// Control/bidi/unicode bytes survive URL-escape round-trips, so they stay.
			seg = strings.ReplaceAll(seg, "/", "_")
			seg = strings.ReplaceAll(seg, "\\", "_")
			seg = strings.ReplaceAll(seg, "\x00", "_")
			if seg == "." || seg == ".." || strings.TrimSpace(seg) == "" {
				seg = "s" + fmt.Sprint(r.intn(50))
			}
			segs = append(segs, seg)
		}
		p := strings.Join(segs, "/")
		if used[p] {
			continue // a duplicate path would be one leaf on the wire; skip to keep the model a tree
		}
		used[p] = true
		l := vLeaf{segs: segs}
		l.state = pickState(r, m.kv2)
		if m.kv2 {
			l.version = 1 + r.intn(7)
			l.created = "2026-01-02T03:04:05Z"
			if r.intn(2) == 0 {
				l.custom = map[string]string{"owner": r.name(), "env": "prod"}
			}
		}
		if l.state == 0 {
			nf := 1 + r.intn(4)
			for j := range nf {
				key := r.name()
				// Occasionally force the single-"value" special case and duplicate keys.
				if nf == 1 && r.intn(2) == 0 {
					key = "value"
				}
				if j > 0 && r.intn(4) == 0 && len(l.fields) > 0 {
					key = l.fields[len(l.fields)-1].key // duplicate key (last-wins on parse)
				}
				core := r.name()
				if r.intn(16) == 0 {
					core = hostile.Canary // leak sentinel as a legit live value
				}
				l.fields = append(l.fields, vField{key: key, val: m.uniqueVal("V", core)})
			}
		}
		m.leaves = append(m.leaves, l)
	}
	for i := range m.leaves {
		m.byPath[m.leaves[i].path()] = &m.leaves[i]
	}
	return m
}

func pickState(r *reader, kv2 bool) int {
	switch r.intn(10) {
	case 0:
		return 3 // empty-leaf
	case 1:
		return 4 // absent
	case 2:
		if kv2 {
			return 1 // soft-deleted
		}
		return 0
	case 3:
		if kv2 {
			return 2 // destroyed
		}
		return 0
	default:
		return 0
	}
}

// sanitizeLite reduces a fragment to a valid Vault mount name: [A-Za-z0-9_-] only. The mount
// is deliberately NOT the hostile surface of these oracles — the secret NAME derives from the
// path/field (which DO carry the full hostile palette); a mount containing "/", "..", NUL or a
// control byte only exercises URL normalisation (owned by FuzzVaultSourceHostileWalk), and a
// ".." segment would be collapsed by net/http path cleaning, breaking the fake server's routing
// for reasons unrelated to import fidelity.
func sanitizeLite(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	if out == "" {
		return "m"
	}
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// ---------------------------------------------------------------------------
// faithful httptest Vault server
// ---------------------------------------------------------------------------

func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }

// renderLeafData renders a live leaf's JSON data object, preserving field order and any
// duplicate keys exactly (so encoding/json's last-wins is genuinely exercised).
func renderLeafData(l *vLeaf) []byte {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, f := range l.fields {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.Write(jsonBytes(f.key))
		sb.WriteByte(':')
		sb.Write(jsonBytes(f.val))
	}
	sb.WriteByte('}')
	return []byte(sb.String())
}

// immediateChildren returns the LIST response keys for a folder prefix: direct children,
// folders suffixed with "/".
func (m *vModel) immediateChildren(prefix string) []string {
	set := map[string]bool{}
	pfx := prefix
	if pfx != "" {
		pfx += "/"
	}
	for _, l := range m.leaves {
		p := l.path()
		if !strings.HasPrefix(p, pfx) {
			continue
		}
		rest := strings.TrimPrefix(p, pfx)
		if rest == "" {
			continue
		}
		if before, _, found := strings.Cut(rest, "/"); found {
			set[before+"/"] = true
		} else {
			set[rest] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// newVaultServer starts an httptest server speaking the Vault KV wire protocol for m.
func (m *vModel) newVaultServer() *httptest.Server {
	mnt := strings.Trim(m.mount, "/")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		w.Header().Set("Content-Type", "application/json")

		// mount version
		if strings.HasPrefix(path, "/v1/sys/internal/ui/mounts/") {
			ver := "1"
			if m.kv2 {
				ver = "2"
			}
			_, _ = w.Write([]byte(`{"data":{"path":"` + mnt + `/","type":"kv","options":{"version":"` + ver + `"}}}`))
			return
		}

		base := "/v1/" + mnt
		var rest string
		switch {
		case path == base:
			rest = "" // root list/read carries no trailing slash
		case strings.HasPrefix(path, base+"/"):
			rest = strings.TrimPrefix(path, base+"/")
		default:
			http.NotFound(w, req)
			return
		}
		isList := req.URL.Query().Get("list") == "true"

		var logical string
		switch {
		case m.kv2 && strings.HasPrefix(rest, "metadata"):
			logical = strings.Trim(strings.TrimPrefix(rest, "metadata"), "/")
		case m.kv2 && strings.HasPrefix(rest, "data"):
			logical = strings.Trim(strings.TrimPrefix(rest, "data"), "/")
		default:
			logical = strings.Trim(rest, "/")
		}

		if isList {
			keys := m.immediateChildren(logical)
			if len(keys) == 0 {
				http.NotFound(w, req) // not a listable folder
				return
			}
			_, _ = w.Write(jsonBytes(map[string]any{"data": map[string]any{"keys": keys}}))
			return
		}

		// READ
		l := m.byPath[logical]
		if l == nil || l.state == 4 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		if !m.kv2 {
			if l.state == 3 {
				_, _ = w.Write([]byte(`{"data":{}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":` + string(renderLeafData(l)) + `}`))
			return
		}
		// KV v2
		meta := map[string]any{
			"version":         l.version,
			"created_time":    l.created,
			"custom_metadata": l.custom,
			"destroyed":       l.state == 2,
		}
		if l.state == 1 {
			meta["deletion_time"] = "2026-01-03T00:00:00Z"
		}
		var dataField any
		switch l.state {
		case 1, 2:
			dataField = nil // soft-deleted/destroyed: null data
		case 3:
			dataField = json.RawMessage(`{}`)
		default:
			dataField = json.RawMessage(renderLeafData(l))
		}
		status := http.StatusOK
		if l.state == 1 || l.state == 2 {
			status = http.StatusNotFound // a deleted/destroyed latest read is a 404 w/ envelope
		}
		w.WriteHeader(status)
		_, _ = w.Write(jsonBytes(map[string]any{"data": map[string]any{"data": dataField, "metadata": meta}}))
	}))
}

// ---------------------------------------------------------------------------
// fake target.API — in-memory Keyorix, modelling the real client's semantics
// ---------------------------------------------------------------------------

// faultMode drives one write seam under the partial-failure oracle.
type faultMode int

const (
	faultOK     faultMode = iota // write succeeds
	faultBefore                  // return error, persist nothing (clean pre-commit failure)
	faultAfter                   // persist atomically, THEN return error (committed, response lost)
)

type storedSecret struct {
	id    int
	name  string
	value string
	meta  map[string]string
}

type fakeStore struct {
	mu     sync.Mutex
	nextID int
	byName map[string]*storedSecret
	byID   map[int]*storedSecret

	// fault schedule: consumed one entry per Create/UpdateValue call. Empty => always OK.
	faults []faultMode
	fpos   int
}

func newFakeStore() *fakeStore {
	return &fakeStore{nextID: 1, byName: map[string]*storedSecret{}, byID: map[int]*storedSecret{}}
}

func (s *fakeStore) nextFault() faultMode {
	if s.fpos >= len(s.faults) {
		return faultOK
	}
	f := s.faults[s.fpos]
	s.fpos++
	return f
}

func (s *fakeStore) LookupByName(_ context.Context, name string) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sec, ok := s.byName[name]; ok {
		return sec.id, true, nil
	}
	return 0, false, nil
}

func (s *fakeStore) Metadata(_ context.Context, id int) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("fakeStore: no secret id %d", id)
	}
	out := map[string]string{}
	maps.Copy(out, sec.meta)
	return out, nil
}

func (s *fakeStore) Value(_ context.Context, id int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.byID[id]
	if !ok {
		return "", fmt.Errorf("fakeStore: no secret id %d", id)
	}
	return sec.value, nil
}

func (s *fakeStore) Create(_ context.Context, name, value string, metadata map[string]string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.nextFault()
	if f == faultBefore {
		return 0, fmt.Errorf("fakeStore: injected pre-commit create failure for %q", name)
	}
	if _, exists := s.byName[name]; exists {
		// The real server enforces per-(project,environment) name uniqueness: a create of an
		// already-existing name is a conflict, not a second row.
		return 0, fmt.Errorf("fakeStore: secret %q already exists (409-equivalent)", name)
	}
	meta := map[string]string{}
	maps.Copy(meta, metadata)
	sec := &storedSecret{id: s.nextID, name: name, value: value, meta: meta}
	s.byName[name] = sec
	s.byID[sec.id] = sec
	s.nextID++
	if f == faultAfter {
		return 0, fmt.Errorf("fakeStore: injected post-commit create failure for %q (row written)", name)
	}
	return sec.id, nil
}

func (s *fakeStore) UpdateValue(_ context.Context, id int, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.nextFault()
	if f == faultBefore {
		return fmt.Errorf("fakeStore: injected pre-commit update failure for id %d", id)
	}
	sec, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("fakeStore: no secret id %d", id)
	}
	sec.value = value
	if f == faultAfter {
		return fmt.Errorf("fakeStore: injected post-commit update failure for id %d (value written)", id)
	}
	return nil
}

// snapshot returns the stored secrets keyed by name (a stable "Keyorix export").
func (s *fakeStore) snapshot() map[string]storedSecret {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]storedSecret{}
	for name, sec := range s.byName {
		cp := *sec
		cp.meta = map[string]string{}
		maps.Copy(cp.meta, sec.meta)
		out[name] = cp
	}
	return out
}
