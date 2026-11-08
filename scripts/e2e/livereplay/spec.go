// Package livereplay is the live-server cross-tenant / cross-role replay
// fuzzer's library: it reads the server's own OpenAPI document, takes the
// requests a legitimate actor (A) made against a real keyorix-server process,
// and replays every one of them as actors that must be refused (another
// tenant, a lower role, no auth, a bad/revoked token, a machine token of
// another project), with object ids swapped to ones A owns, mutated ids,
// pagination/filter mutation and batch bodies. The oracle is deny-direction
// only: a success, a state change, or a leaked canary for an actor the model
// says must be refused is a CANDIDATE finding, never a verdict.
//
// This file is the OpenAPI reader. It has no test tag so the library and its
// self-tests run in the default `go test`; only the live-server driver
// (live_e2e_test.go) needs `-tags e2e`.
package livereplay

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Param is one path or query parameter.
type Param struct {
	Name     string
	In       string // "path" or "query"
	Required bool
	Type     string
	Enum     []any
}

// Op is one OpenAPI operation.
type Op struct {
	Method      string // upper case
	Path        string // template, e.g. /api/v1/secrets/{id}
	OperationID string
	Public      bool // security: [] (explicitly unauthenticated)
	Params      []Param
	Body        map[string]any // resolved JSON request schema, nil when none
	Summary     string
}

// Key is the stable identity "METHOD /path/template".
func (o Op) Key() string { return o.Method + " " + o.Path }

// Spec is a parsed OpenAPI document.
type Spec struct {
	doc map[string]any
	Ops []Op
}

// LoadSpec parses the OpenAPI YAML at path.
func LoadSpec(path string) (*Spec, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- caller-supplied repo path, test tooling
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s := &Spec{doc: doc}
	paths, _ := doc["paths"].(map[string]any)
	for p, item := range paths {
		im, _ := item.(map[string]any)
		var shared []Param
		if pl, ok := im["parameters"].([]any); ok {
			shared = s.params(pl)
		}
		for m, opv := range im {
			switch m {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			om, _ := opv.(map[string]any)
			op := Op{Method: strings.ToUpper(m), Path: p}
			op.OperationID, _ = om["operationId"].(string)
			op.Summary, _ = om["summary"].(string)
			if sec, ok := om["security"].([]any); ok && len(sec) == 0 {
				op.Public = true
			}
			op.Params = append(op.Params, shared...)
			if pl, ok := om["parameters"].([]any); ok {
				op.Params = append(op.Params, s.params(pl)...)
			}
			if rb, ok := om["requestBody"].(map[string]any); ok {
				rb = s.resolve(rb)
				if c, ok := rb["content"].(map[string]any); ok {
					if j, ok := c["application/json"].(map[string]any); ok {
						if sch, ok := j["schema"].(map[string]any); ok {
							op.Body = s.resolve(sch)
						}
					}
				}
			}
			s.Ops = append(s.Ops, op)
		}
	}
	sort.Slice(s.Ops, func(i, j int) bool { return s.Ops[i].Key() < s.Ops[j].Key() })
	return s, nil
}

func (s *Spec) params(pl []any) []Param {
	var out []Param
	for _, pv := range pl {
		pm, _ := pv.(map[string]any)
		pm = s.resolve(pm)
		p := Param{}
		p.Name, _ = pm["name"].(string)
		p.In, _ = pm["in"].(string)
		p.Required, _ = pm["required"].(bool)
		if sch, ok := pm["schema"].(map[string]any); ok {
			sch = s.resolve(sch)
			p.Type, _ = sch["type"].(string)
			p.Enum, _ = sch["enum"].([]any)
		}
		if p.In == "path" || p.In == "query" {
			out = append(out, p)
		}
	}
	return out
}

// resolve follows a local $ref chain.
func (s *Spec) resolve(m map[string]any) map[string]any {
	for range 16 {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		cur := any(s.doc)
		for k := range strings.SplitSeq(strings.TrimPrefix(ref, "#/"), "/") {
			cm, ok := cur.(map[string]any)
			if !ok {
				return m
			}
			cur = cm[k]
		}
		nm, ok := cur.(map[string]any)
		if !ok {
			return m
		}
		m = nm
	}
	return m
}

// MinimalBody builds a schema-valid JSON value from the op's request schema:
// required properties only (or the first few when none are marked), enum
// first value, formats honoured. Used only for ops the recorded session did
// not itself exercise; a body the server rejects as invalid makes the probe
// INCONCLUSIVE, never a finding.
func (s *Spec) MinimalBody(o Op) any {
	if o.Body == nil {
		return nil
	}
	return s.gen(o.Body, "body", 0)
}

func (s *Spec) gen(sch map[string]any, name string, depth int) any {
	sch = s.resolve(sch)
	if depth > 4 {
		return nil
	}
	if ex, ok := sch["example"]; ok {
		return ex
	}
	if d, ok := sch["default"]; ok {
		return d
	}
	if e, ok := sch["enum"].([]any); ok && len(e) > 0 {
		return e[0]
	}
	if ao, ok := sch["allOf"].([]any); ok && len(ao) > 0 {
		merged := map[string]any{}
		for _, part := range ao {
			if pm, ok := part.(map[string]any); ok {
				if g, ok := s.gen(pm, name, depth+1).(map[string]any); ok {
					maps.Copy(merged, g)
				}
			}
		}
		return merged
	}
	for _, k := range []string{"oneOf", "anyOf"} {
		if ao, ok := sch[k].([]any); ok && len(ao) > 0 {
			if pm, ok := ao[0].(map[string]any); ok {
				return s.gen(pm, name, depth+1)
			}
		}
	}
	switch sch["type"] {
	case "object", nil:
		props, _ := sch["properties"].(map[string]any)
		if props == nil {
			return map[string]any{}
		}
		req := map[string]bool{}
		if rl, ok := sch["required"].([]any); ok {
			for _, r := range rl {
				if rs, ok := r.(string); ok {
					req[rs] = true
				}
			}
		}
		out := map[string]any{}
		names := make([]string, 0, len(props))
		for k := range props {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if len(req) > 0 && !req[k] {
				continue
			}
			if len(req) == 0 && len(out) >= 4 {
				break
			}
			pm, _ := props[k].(map[string]any)
			out[k] = s.gen(pm, k, depth+1)
		}
		return out
	case "array":
		items, _ := sch["items"].(map[string]any)
		if items == nil {
			return []any{}
		}
		return []any{s.gen(items, name, depth+1)}
	case "integer", "number":
		return 1
	case "boolean":
		return false
	case "string":
		switch sch["format"] {
		case "email":
			return "lr-" + safeName(name) + "@example.invalid"
		case "date-time":
			return "2031-01-02T03:04:05Z"
		case "date":
			return "2031-01-02"
		case "uri", "url":
			return "https://example.invalid/lr"
		}
		return "lr-" + safeName(name)
	}
	return nil
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func safeName(s string) string { return strings.ToLower(unsafeName.ReplaceAllString(s, "-")) }

var pathParamRE = regexp.MustCompile(`\{([^}]+)\}`)

// PathParams returns the template's parameter names in order.
func PathParams(path string) []string {
	var out []string
	for _, m := range pathParamRE.FindAllStringSubmatch(path, -1) {
		out = append(out, m[1])
	}
	return out
}

// ParamKind infers which kind of object a path parameter names from the path
// segment that precedes it ("/projects/{id}" -> project). The kinds are the
// keys of World.IDs.
func ParamKind(path, param string) string {
	idx := strings.Index(path, "{"+param+"}")
	if idx < 0 {
		return ""
	}
	segs := strings.Split(strings.Trim(path[:idx], "/"), "/")
	if len(segs) == 0 {
		return ""
	}
	prev := segs[len(segs)-1]
	switch prev {
	case "projects":
		return "project"
	case "secrets":
		return "secret"
	case "environments":
		return "env"
	case "groups":
		return "group"
	case "users", "user":
		return "user"
	case "roles":
		return "role"
	case "machine-identities":
		return "machine"
	case "tokens":
		if strings.Contains(path[:idx], "machine-identities") {
			return "machinetoken"
		}
		return "pat"
	case "shares":
		return "share"
	case "acl":
		return "acl"
	case "invitations":
		return "invitation"
	case "access-requests", "secret-access-requests":
		return "accessrequest"
	case "members", "memberships":
		return "user"
	case "versions":
		return "version"
	}
	return strings.TrimSuffix(prev, "s")
}
