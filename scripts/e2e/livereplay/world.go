package livereplay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Recorded is one request the legitimate actor made during the recorded
// session, with the status it got.
type Recorded struct {
	Method string
	Path   string // concrete, no query
	Query  string
	Body   []byte
	Status int
}

// World is everything the replay needs to know about the system under test:
// who the actors are, which object ids each tenant owns, what the recorded
// legitimate session looked like, and which read-only requests fingerprint
// the system state.
type World struct {
	BaseURL string
	Spec    *Spec
	Actors  map[string]*Actor
	// Attackers is the deterministic order actors are replayed in. It should
	// include the legitimate actor (name "A") last as the positive control.
	Attackers []string
	// IDs: tenant -> kind -> ids. Kinds come from ParamKind.
	IDs map[string]map[string][]string
	// Marker: tenant -> lower-case prefix every name/value of that tenant
	// carries, e.g. "lrcanary-a-". A response that contains another tenant's
	// marker is a leak.
	Marker map[string]string
	// Refs: tenant -> "project/env/secret" reference of a tenant secret, for
	// the by-reference read routes.
	Refs map[string]string
	// Recorded legitimate requests, by Op.Key().
	Recorded map[string][]Recorded
	// Observer is a global-admin credential used only to read state for the
	// effect oracle. It never takes part in replay.
	Observer *Actor
	// FPPaths are the GET paths whose bodies make up the state fingerprint.
	FPPaths []string
	// FPTenant tags each FPPath with the tenant whose state it shows ("" =
	// shared/global). An actor may legitimately change its own tenant's state.
	FPTenant map[string]string
	// Client is the HTTP client every request goes through.
	Client *http.Client

	mu        sync.Mutex
	Throttled int
}

// NewWorld returns an empty world bound to baseURL.
func NewWorld(baseURL string, spec *Spec) *World {
	w := &World{
		BaseURL:  baseURL,
		Spec:     spec,
		Actors:   map[string]*Actor{},
		IDs:      map[string]map[string][]string{"A": {}, "B": {}},
		Marker:   map[string]string{"A": "lrcanary-a-", "B": "lrcanary-b-"},
		Refs:     map[string]string{},
		Recorded: map[string][]Recorded{},
		Client:   &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	return w
}

// AddID registers an object id under tenant/kind.
func (w *World) AddID(tenant, kind string, id string) {
	if w.IDs[tenant] == nil {
		w.IDs[tenant] = map[string][]string{}
	}
	w.IDs[tenant][kind] = append(w.IDs[tenant][kind], id)
}

// FirstID returns the tenant's first id of kind.
func (w *World) FirstID(tenant, kind string) (string, bool) {
	ids := w.IDs[tenant][kind]
	if len(ids) == 0 {
		return "", false
	}
	return ids[0], true
}

// Do sends one request as actor and returns status and (capped) body. 429 is
// retried a few times with the server's own Retry-After and counted.
func (w *World) Do(a *Actor, method, target string, body []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, w.BaseURL+target, rd)
		if err != nil {
			return 0, nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if a != nil && a.Token != "" {
			req.Header.Set("Authorization", "Bearer "+a.Token)
		}
		resp, err := w.Client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 4 {
			w.mu.Lock()
			w.Throttled++
			w.mu.Unlock()
			d := 2 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if n, err := time.ParseDuration(ra + "s"); err == nil && n < 20*time.Second {
					d = n
				}
			}
			time.Sleep(d)
			continue
		}
		return resp.StatusCode, b, nil
	}
}

// Record sends a request as the legitimate actor and stores it in the
// recorded session keyed by the OpenAPI operation it matches.
func (w *World) Record(a *Actor, method, target string, body []byte) (int, []byte, error) {
	status, resp, err := w.Do(a, method, target, body)
	if err != nil {
		return status, resp, err
	}
	path, query := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path, query = target[:i], target[i+1:]
	}
	if op, ok := w.matchOp(method, path); ok {
		w.Recorded[op.Key()] = append(w.Recorded[op.Key()], Recorded{Method: method, Path: path, Query: query, Body: body, Status: status})
	}
	return status, resp, nil
}

func (w *World) matchOp(method, path string) (Op, bool) {
	if w.Spec == nil {
		return Op{}, false
	}
	for _, op := range w.Spec.Ops {
		if op.Method != method {
			continue
		}
		parts := pathParamRE.Split(op.Path, -1)
		re := "^"
		for i, p := range parts {
			re += regexp.QuoteMeta(p)
			if i < len(parts)-1 {
				re += `[^/]+`
			}
		}
		re += "$"
		if ok, _ := regexp.MatchString(re, path); ok {
			return op, true
		}
	}
	return Op{}, false
}

var volatileKey = regexp.MustCompile(`(?i)(_at$|time|^last|count|accessed|updated|created|expir|^token$|nonce|etag|checksum|duration|^ts$)`)

// stable removes volatile keys from decoded JSON so two reads of unchanged
// state hash equal.
func stable(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if volatileKey.MatchString(k) {
				continue
			}
			out[k] = stable(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = stable(x)
		}
		return out
	}
	return v
}

// Fingerprint hashes each FPPath as the observer. The returned map is path ->
// digest; compare two of them with Changed.
func (w *World) Fingerprint() map[string]string {
	out := map[string]string{}
	for _, p := range w.FPPaths {
		status, body, err := w.Do(w.Observer, "GET", p, nil)
		if err != nil {
			out[p] = "error:" + err.Error()
			continue
		}
		var v any
		if json.Unmarshal(body, &v) == nil {
			if nb, err := json.Marshal(stable(v)); err == nil {
				body = nb
			}
		}
		h := sha256.Sum256(append([]byte{byte(status / 100)}, body...))
		out[p] = hex.EncodeToString(h[:8])
	}
	return out
}

// Changed lists the paths whose digest differs.
func Changed(before, after map[string]string) []string {
	var out []string
	for p, d := range after {
		if before[p] != d {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
