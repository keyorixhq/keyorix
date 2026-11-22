package k8ssync

// fetcher_hostile_fuzz_test.go: FuzzKeyorixFetcherHostileServer is the
// hostile-backend record-and-mutate target for the k8ssync Keyorix fetcher
// (rules: internal/fuzzutil/hostile/RULES.md). The fetcher resolves
// "<environment>/<name>" through three calls (environments, a paginated secret
// list, the secret value) and the result is written into a Kubernetes Secret,
// so a fail-open here puts a wrong, partial or empty value into a workload.
//
// The value route serves a DIFFERENT value for any secret id other than the one
// the pristine list names, so reading the wrong secret is visible. Strict
// decoders follow the documented Keyorix REST envelope ({"data": ...}) and the
// scope rule: the matching list entry and the value response must name project
// 7 and the resolved environment, and the value response the id that was read.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileFetchToken = "kx-hostile-fetcher-token-3b9a"
	hostileFetchValue = "s3cr3t-db-password"
)

type fetchObs struct {
	mu        sync.Mutex
	listEnvID []string
	valueIDs  []string
}

func fetcherHostileRoutes(o *fetchObs) []hostile.Route {
	js := func(s string) hostile.Resp {
		return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)}
	}
	return []hostile.Route{
		{Name: "envs", Method: "GET", Prefix: "/api/v1/projects/7/environments", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"data":{"environments":[{"ID":3,"Name":"prod"},{"ID":4,"Name":"stage"}]}}`)
		}},
		{Name: "list", Method: "GET", Prefix: "/api/v1/secrets", Valid: func(_ int, r *http.Request) hostile.Resp {
			o.mu.Lock()
			o.listEnvID = append(o.listEnvID, r.URL.Query().Get("environment_id"))
			o.mu.Unlock()
			return js(`{"data":{"secrets":[` +
				`{"ID":41,"Name":"other","project_id":7,"environment_id":3},` +
				`{"ID":42,"Name":"db-pass","project_id":7,"environment_id":3}],"total_pages":1,"page":1}}`)
		}},
		{Name: "value", Method: "GET", Prefix: "/api/v1/secrets/", Valid: func(_ int, r *http.Request) hostile.Resp {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
			o.mu.Lock()
			o.valueIDs = append(o.valueIDs, id)
			o.mu.Unlock()
			// The fetcher builds the path from a uint, so id is a decimal number.
			scope := `"secret":{"id":` + id + `,"project_id":7,"environment_id":3,"expiration":null}`
			if id == "42" {
				return js(`{"data":{"value":"` + hostileFetchValue + `",` + scope + `}}`)
			}
			return js(`{"data":{"value":"OTHER-SECRETS-VALUE",` + scope + `}}`)
		}},
	}
}

func strictFetchEnv(b []byte, want string) (string, bool) {
	var d struct {
		Data *struct {
			Envs []struct {
				ID   json.Number `json:"ID"`
				Name string      `json:"Name"`
			} `json:"environments"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil || d.Data == nil {
		return "", false
	}
	for _, e := range d.Data.Envs {
		if e.Name == want {
			if _, err := strconv.ParseUint(e.ID.String(), 10, 64); err == nil {
				return e.ID.String(), true
			}
		}
	}
	return "", false
}

// hostileFetchProject is the project the harness's fetcher is built with; a
// strictly valid list entry or value response names it as its project_id.
const hostileFetchProject = "7"

// strictUint is the decimal form of a JSON number that is a uint64, and false
// for anything else (missing, null, a string, a fraction, out of range).
func strictUint(raw json.RawMessage) (string, bool) {
	if _, err := strconv.ParseUint(string(raw), 10, 64); err != nil {
		return "", false
	}
	return string(raw), true
}

// strictFetchListID finds the first entry named want with a valid id (matched)
// and reports it ok only when that entry is scoped to hostileFetchProject and
// env. A first match in another scope is refused, not skipped: the fetcher
// applies the same rule.
func strictFetchListID(b []byte, want, env string) (id string, matched, ok bool) {
	var d struct {
		Data *struct {
			Secrets []struct {
				ID            json.Number     `json:"ID"`
				Name          string          `json:"Name"`
				ProjectID     json.RawMessage `json:"project_id"`
				EnvironmentID json.RawMessage `json:"environment_id"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil || d.Data == nil {
		return "", false, false
	}
	for _, s := range d.Data.Secrets {
		if s.Name == want {
			if _, err := strconv.ParseUint(s.ID.String(), 10, 64); err == nil {
				p, pok := strictUint(s.ProjectID)
				e, eok := strictUint(s.EnvironmentID)
				return s.ID.String(), true, pok && eok && p == hostileFetchProject && e == env
			}
		}
	}
	return "", false, false
}

func strictFetchValue(b []byte) (string, bool) {
	var d struct {
		Data *struct {
			Value *string `json:"value"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil || d.Data == nil || d.Data.Value == nil || *d.Data.Value == "" {
		return "", false
	}
	return *d.Data.Value, true
}

// strictValueScoped reports whether a value response says it is secret id in
// hostileFetchProject and env, the rule the fetcher applies before using it.
func strictValueScoped(b []byte, id, env string) bool {
	var d struct {
		Data *struct {
			Secret *struct {
				ID            json.RawMessage `json:"id"`
				ProjectID     json.RawMessage `json:"project_id"`
				EnvironmentID json.RawMessage `json:"environment_id"`
			} `json:"secret"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil || d.Data == nil || d.Data.Secret == nil {
		return false
	}
	s := d.Data.Secret
	i, iok := strictUint(s.ID)
	p, pok := strictUint(s.ProjectID)
	e, eok := strictUint(s.EnvironmentID)
	return iok && pok && eok && i == id && p == hostileFetchProject && e == env
}

func FuzzKeyorixFetcherHostileServer(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Route: 1, Occ: 1, Ops: []hostile.Op{{Code: 8, A: 9, B: 7}}}, // total_pages huge
		{Route: 1, Occ: 1, Ops: []hostile.Op{{Code: 1, A: 5}}},       // match removed on every page
		{Route: 1, Ops: []hostile.Op{{Code: 3, A: 8, B: 0x81}}},      // duplicate Name
		{Route: 1, Ops: []hostile.Op{{Code: 6, A: 7, B: 14}}},        // ID -> canary string
		{Route: 0, Ops: []hostile.Op{{Code: 6, A: 3, B: 14}}},        // env ID -> canary
		{Route: 2, Redir: 3}, {Route: 2, Redir: 1}, {Route: 2, Frame: 3},
		{Route: 2, Fault: 2}, {Route: 2, Enc: 2}, {Route: 2, Trunc: 20}, {Route: 1, Status: 16},
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		h := runFetcherHostile(hostile.Decode(prog), fetcherKnown)
		defer h.Close()
		h.Finish(t.Fatalf)
	})
}

// fetcherKnown lists this target's triaged, still-open findings (hostile.Known;
// issue-ready text in the m32 report). Each has a reproducer test below.
var fetcherKnown = []hostile.Known{{
	// HARDENING: getJSON decodes ONE JSON value with json.Decoder and then
	// drainAndClose discards the rest, so a transport/integrity error that
	// surfaces only after the complete value (corrupt gzip CRC, declared
	// Content-Length longer than sent, unterminated chunked body) is never seen.
	// The value itself was delivered completely.
	ID:     "HK-FETCHER-TRAILING-TRANSPORT-ERROR",
	Class:  "HARDENING",
	Prefix: "O5/transport-error-ignored: fetch succeeded",
	// Input e16ff2665a232884: route=envs enc=gzip-corrupt.
	Repro: hostile.Program{Route: 0, Enc: 3},
}, {
	// EXPECTED-DIFFERENCE: getJSON accepts any 2xx (keyorix_fetcher.go), the
	// Keyorix server answers these GETs with 200. Only the sub-tag is
	// suppressed: every value check passed on complete bodies.
	ID:     "HK-FETCHER-ANY-2XX",
	Class:  "EXPECTED-DIFFERENCE",
	Prefix: "O5/bad-status-accepted/2xx-valid-body: fetch",
	// Directed: route=value status=206.
	Repro: hostile.Program{Route: 2, Status: 5},
}}

// TestFetcherHostileKnownFindingsReproduce replays every fetcherKnown entry
// with the entry NOT applied; it goes red when a finding is fixed.
func TestFetcherHostileKnownFindingsReproduce(t *testing.T) {
	for _, k := range fetcherKnown {
		t.Run(k.ID, func(t *testing.T) {
			h := runFetcherHostile(k.Repro, nil)
			defer h.Close()
			hostile.RequireKnownReproduces(t, k, h)
		})
	}
}

// runFetcherHostile runs one program against the real fetcher and applies the
// target's oracles; the caller calls Finish (fuzz) or Evaluate (reproducer).
func runFetcherHostile(p hostile.Program, known []hostile.Known) *hostile.Harness {
	obs := &fetchObs{}
	h := hostile.New(hostile.Config{
		Routes: fetcherHostileRoutes(obs), Program: p,
		Credentials: []string{hostileFetchToken}, RequestCeiling: 64,
		Known: known,
	})
	fe := NewKeyorixFetcher(h.URL(), hostileFetchToken, 7)

	var val []byte
	err := h.Run("KeyorixFetcher.FetchWithExpiry", func(ctx context.Context) error {
		var e error
		val, _, e = fe.FetchWithExpiry(ctx, "prod/db-pass")
		return e
	})
	if p.Pristine() && (err != nil || string(val) != hostileFetchValue) {
		h.Violate("O6 LIVENESS: pristine fetch returned %q, %v (unmatched: %v)", val, err, h.Unmatched())
	}
	if err == nil {
		// The strict list and value decoders need the scope the earlier
		// responses establish: the environment id from the delivered environment
		// list, then the first id the delivered list pages assign to the name.
		var wantEnv, wantID string
		var envOK bool
		deliver := func(okStatus []int) (envBody, valBody []byte, ek, lk, vk string) {
			envBody, ek = h.Delivery("envs", func(b []byte) bool { _, ok := strictFetchEnv(b, "prod"); return ok }, okStatus...)
			wantEnv, envOK = strictFetchEnv(envBody, "prod")
			wantID = ""
			for _, rec := range h.Served("list") {
				// Not rec.Complete: a page whose whole content arrived before a
				// trailing transport error (O5/transport-error-ignored, reported
				// separately) was delivered; Seen holds only what the client could read.
				// The first match decides, in or out of scope, as in the fetcher.
				if id, matched, ok := strictFetchListID(rec.Seen, "db-pass", wantEnv); matched && slices.Contains(okStatus, rec.Status) {
					if ok {
						wantID = id
					}
					break
				}
			}
			_, lk = h.Delivery("list", func(b []byte) bool { _, _, ok := strictFetchListID(b, "db-pass", wantEnv); return ok }, okStatus...)
			valBody, vk = h.Delivery("value", func(b []byte) bool {
				_, ok := strictFetchValue(b)
				return ok && strictValueScoped(b, wantID, wantEnv)
			}, okStatus...)
			return envBody, valBody, ek, lk, vk
		}
		okStatus := []int{200}
		envBody, valBody, ek, lk, vk := deliver(okStatus)
		// The fetcher accepts any 2xx by design. A final 2xx other than 200 used
		// to skip every value check below; it is now judged like a 200, and a
		// success that passes them all is tagged /2xx-valid-body (a Known entry
		// names exactly that).
		other2xx := false
		if (ek == "status" || lk == "status" || vk == "status") && servedAll2xx(h) {
			okStatus, other2xx = hostile.Status2xx, true
			envBody, valBody, ek, lk, vk = deliver(okStatus)
		}
		want, valOK := strictFetchValue(valBody)
		valScoped := strictValueScoped(valBody, wantID, wantEnv)
		obs.mu.Lock()
		gotIDs := append([]string(nil), obs.valueIDs...)
		listEnvs := append([]string(nil), obs.listEnvID...)
		obs.mu.Unlock()

		valueOK := false
		switch {
		case ek == "status" || lk == "status" || vk == "status":
			h.Violate("O5/bad-status-accepted: fetch succeeded (%q) on a response whose final HTTP status was not 200 (env=%q list=%q value=%q)", val, ek, lk, vk)
		case ek == "bad" || lk == "bad" || vk == "bad":
			h.Violate("O5/incomplete: fetch succeeded (%q) although a consumed exchange was incomplete, redirected or non-200 (env=%q list=%q value=%q)", val, ek, lk, vk)
		case hostile.HasDuplicateKeys(envBody) || hostile.HasDuplicateKeys(valBody) || listHasDup(h):
			// duplicate member names: no single correct reading (RFC 8259)
		case !valOK:
			h.Violate("O5/empty-value: fetch succeeded with %q but the delivered value response has no non-empty data.value", val)
		case string(val) != want:
			h.Violate("O5/value: fetch returned %q, strict decoder %q", val, want)
		case !envOK || (len(listEnvs) > 0 && listEnvs[0] != wantEnv):
			h.Violate("O5/environment: list scoped to environment_id %v, strict environment id %q (valid=%v)", listEnvs, wantEnv, envOK)
		case wantID == "" || len(gotIDs) == 0 || gotIDs[len(gotIDs)-1] != wantID:
			// wantID is empty also when the first match is listed outside project 7
			// or the strict environment.
			h.Violate("O5/secret-id: value read from id %v, strict first in-scope match in delivered list %q", gotIDs, wantID)
		case !valScoped:
			h.Violate("O5/value-scope: fetch returned %q from a value response not scoped to secret %s, project %s, environment %s", val, wantID, hostileFetchProject, wantEnv)
		default:
			valueOK = true
		}
		if other2xx && valueOK && ek == "" && lk == "" && vk == "" {
			h.Violate("O5/bad-status-accepted/2xx-valid-body: fetch succeeded (%q) on a final 2xx other than 200 with complete bodies the strict decoders agree with", val)
		}
		if ek == "transport" || lk == "transport" || vk == "transport" {
			h.Violate("O5/transport-error-ignored: fetch succeeded although a response ended in a transport/framing/gzip error after the full JSON value")
		}
	}
	return h
}

func listHasDup(h *hostile.Harness) bool {
	for _, rec := range h.Served("list") {
		if hostile.HasDuplicateKeys(rec.Seen) {
			return true
		}
	}
	return false
}

// servedAll2xx reports whether every response the fetcher consumed ended with a
// 2xx status. The fetcher treats any 2xx as success, which is accepted
// behaviour (see RULES.md, classification "expected"); only non-2xx is a defect.
func servedAll2xx(h *hostile.Harness) bool {
	for _, r := range []string{"envs", "list", "value"} {
		for _, rec := range h.Served(r) {
			if rec.Status != 0 && (rec.Status < 200 || rec.Status > 299) {
				return false
			}
		}
	}
	return true
}
