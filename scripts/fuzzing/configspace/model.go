// Package configspace is a covering-array fuzzer for keyorix-server's startup
// configuration surface. See README.md and RULES.md in this directory.
package configspace

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed model.yaml
var modelYAML []byte

// Value classes.
const (
	ClassValid    = "valid"
	ClassBoundary = "boundary"
	ClassEmpty    = "empty"
	ClassAbsent   = "absent"
	ClassInvalid  = "invalid"
)

// Param kinds.
const (
	KindYAML = "yaml"
	KindEnv  = "env"
	KindArg  = "arg"
)

// Value is one assignable value of a parameter.
type Value struct {
	V         any    `yaml:"v"`
	Absent    bool   `yaml:"absent"`
	Class     string `yaml:"c"`
	Startable *bool  `yaml:"startable"`
	Fallback  string `yaml:"fallback"`
	Note      string `yaml:"note"`
	// With lists YAML paths that are set (before the case's own assignments are
	// applied, so an explicit assignment wins) to enable the feature the value
	// belongs to. Without it an invalid value of a conditionally-validated option
	// would be accepted only because its feature is off.
	With map[string]any `yaml:"with"`
}

// CanStart reports whether a row containing this value can start in the sandbox.
func (v Value) CanStart() bool { return v.Startable == nil || *v.Startable }

// Param is one configuration option (a YAML key, an environment variable, or a flag).
type Param struct {
	ID     string  `yaml:"id"`
	Path   string  `yaml:"path"`
	Kind   string  `yaml:"kind"`
	Group  string  `yaml:"group"`
	Values []Value `yaml:"values"`
}

// Conflict is a contradiction the code must refuse (I2b).
type Conflict struct {
	ID    string           `yaml:"id"`
	When  map[string][]any `yaml:"when"`
	Names []string         `yaml:"names"`
	Note  string           `yaml:"note"`
}

// PostureRule is an independent insecure-posture predicate (I3).
type PostureRule struct {
	ID       string   `yaml:"id"`
	What     string   `yaml:"what"`
	Warn     string   `yaml:"warn"`
	Explicit []string `yaml:"explicit"`
	warnRE   *regexp.Regexp
}

// Normalisation is a documented difference between written and effective value.
type Normalisation struct {
	Path string `yaml:"path"`
	Why  string `yaml:"why"`
}

// Model is the parsed model.yaml.
type Model struct {
	Version         int             `yaml:"version"`
	Normalisations  []Normalisation `yaml:"normalisations"`
	Params          []Param         `yaml:"params"`
	Conflicts       []Conflict      `yaml:"conflicts"`
	Posture         []PostureRule   `yaml:"posture"`
	byID            map[string]*Param
	normalisedPaths map[string]bool
}

// LoadModel parses the embedded model and validates its internal consistency.
func LoadModel() (*Model, error) { return ParseModel(modelYAML) }

// ParseModel parses and validates a model document.
func ParseModel(data []byte) (*Model, error) {
	var m Model
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("model.yaml: %w", err)
	}
	m.byID = map[string]*Param{}
	m.normalisedPaths = map[string]bool{}
	for _, n := range m.Normalisations {
		m.normalisedPaths[n.Path] = true
	}
	paths := map[string]bool{}
	for i := range m.Params {
		p := &m.Params[i]
		if p.Kind == "" {
			p.Kind = KindYAML
		}
		if p.ID == "" || p.Path == "" {
			return nil, fmt.Errorf("model.yaml: param %d has no id or path", i)
		}
		if m.byID[p.ID] != nil {
			return nil, fmt.Errorf("model.yaml: duplicate param id %q", p.ID)
		}
		if paths[p.Kind+":"+p.Path] {
			return nil, fmt.Errorf("model.yaml: duplicate param path %q", p.Path)
		}
		paths[p.Kind+":"+p.Path] = true
		m.byID[p.ID] = p
		if len(p.Values) < 2 {
			return nil, fmt.Errorf("model.yaml: param %q has fewer than two values", p.ID)
		}
		for j := range p.Values {
			v := &p.Values[j]
			switch v.Class {
			case ClassValid, ClassBoundary, ClassEmpty, ClassAbsent, ClassInvalid:
			default:
				return nil, fmt.Errorf("model.yaml: param %q value %d has class %q", p.ID, j, v.Class)
			}
			if (v.Class == ClassAbsent) != v.Absent {
				return nil, fmt.Errorf("model.yaml: param %q value %d: class absent and absent: true must agree", p.ID, j)
			}
		}
	}
	for i := range m.Posture {
		re, err := regexp.Compile(m.Posture[i].Warn)
		if err != nil {
			return nil, fmt.Errorf("model.yaml: posture %s: %w", m.Posture[i].ID, err)
		}
		m.Posture[i].warnRE = re
	}
	return &m, nil
}

// Param returns a parameter by id.
func (m *Model) Param(id string) *Param { return m.byID[id] }

// Normalised reports whether a path is a documented normalisation.
func (m *Model) Normalised(path string) bool { return m.normalisedPaths[path] }

// PostureRule returns a posture rule by id.
func (m *Model) PostureRule(id string) *PostureRule {
	for i := range m.Posture {
		if m.Posture[i].ID == id {
			return &m.Posture[i]
		}
	}
	return nil
}

// Counts summarises the size of the model.
type Counts struct {
	Params, Values, Invalid, YAML, Env, Arg int
	Groups                                  []string
}

// Counts returns model size figures.
func (m *Model) Counts() Counts {
	var c Counts
	groups := map[string]bool{}
	for _, p := range m.Params {
		c.Params++
		groups[p.Group] = true
		switch p.Kind {
		case KindYAML:
			c.YAML++
		case KindEnv:
			c.Env++
		case KindArg:
			c.Arg++
		}
		for _, v := range p.Values {
			c.Values++
			if v.Class == ClassInvalid {
				c.Invalid++
			}
		}
	}
	for g := range groups {
		c.Groups = append(c.Groups, g)
	}
	sort.Strings(c.Groups)
	return c
}

// IsSecretPath reports whether a dotted YAML path names a secret-bearing field.
func IsSecretPath(path string) bool {
	last := path
	if _, after, ok := strings.CutLast(path, "."); ok {
		last = after
	}
	switch {
	case strings.HasSuffix(last, "_file"), strings.HasSuffix(last, "_env"), strings.HasSuffix(last, "_path"):
		return false
	case strings.Contains(last, "password"), strings.Contains(last, "token"), strings.Contains(last, "secret"),
		last == "dsn", last == "api_key", strings.Contains(last, "signing"):
		return true
	}
	return false
}
