package main

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Spec indexes the OpenAPI document: path template -> METHOD -> declared query parameters.
type Spec struct {
	ops map[string]map[string]map[string]bool
}

func loadSpec(path string) (*Spec, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied spec path
	if err != nil {
		return nil, err
	}
	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Parameters map[string]map[string]any `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	s := &Spec{ops: map[string]map[string]map[string]bool{}}
	paramName := func(p any) (name, in string) {
		m, ok := p.(map[string]any)
		if !ok {
			return "", ""
		}
		if ref, ok := m["$ref"].(string); ok {
			if c, ok := doc.Components.Parameters[ref[strings.LastIndex(ref, "/")+1:]]; ok {
				m = c
			}
		}
		n, _ := m["name"].(string)
		i, _ := m["in"].(string)
		return n, i
	}
	for tmpl, item := range doc.Paths {
		common := map[string]bool{}
		if ps, ok := item["parameters"].([]any); ok {
			for _, p := range ps {
				if n, in := paramName(p); in == "query" {
					common[n] = true
				}
			}
		}
		s.ops[tmpl] = map[string]map[string]bool{}
		for m, op := range item {
			um := strings.ToUpper(m)
			switch um {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue
			}
			q := map[string]bool{}
			for k := range common {
				q[k] = true
			}
			if om, ok := op.(map[string]any); ok {
				if ps, ok := om["parameters"].([]any); ok {
					for _, p := range ps {
						if n, in := paramName(p); in == "query" {
							q[n] = true
						}
					}
				}
			}
			s.ops[tmpl][um] = q
		}
	}
	return s, nil
}

func (s *Spec) match(path string) (string, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var cands []string
	for tmpl := range s.ops {
		ts := strings.Split(strings.Trim(tmpl, "/"), "/")
		if len(ts) != len(segs) {
			continue
		}
		ok := true
		for i := range ts {
			if strings.HasPrefix(ts[i], "{") {
				if segs[i] == "" {
					ok = false
				}
				continue
			}
			if ts[i] != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			cands = append(cands, tmpl)
		}
	}
	if len(cands) == 0 {
		return "", false
	}
	sort.Slice(cands, func(i, j int) bool { return strings.Count(cands[i], "{") < strings.Count(cands[j], "{") })
	return cands[0], true
}

// Check returns "" when the request conforms, else a short reason used as the finding shape.
func (s *Spec) Check(method, requestURI string) string {
	rawPath, rawQ, _ := strings.Cut(requestURI, "?")
	p, err := url.PathUnescape(rawPath)
	if err != nil {
		p = rawPath
	}
	tmpl, ok := s.match(p)
	if !ok {
		return "undeclared-path"
	}
	q, ok := s.ops[tmpl][strings.ToUpper(method)]
	if !ok {
		return "undeclared-method " + method + " " + tmpl
	}
	vals, err := url.ParseQuery(rawQ)
	if err != nil {
		return "unparsable-query " + tmpl
	}
	var bad []string
	for k := range vals {
		if !q[k] {
			bad = append(bad, k)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		return fmt.Sprintf("undeclared-query %s %s", method+" "+tmpl, strings.Join(bad, ","))
	}
	return ""
}
