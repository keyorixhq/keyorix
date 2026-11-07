package configspace

import (
	"crypto/sha1" // #nosec G505 -- non-cryptographic, derives stable canary markers
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Case is one configuration to exercise: a set of parameter assignments applied on top
// of the secure baseline. Assign maps a parameter id to a value index.
type Case struct {
	ID     string
	Kind   string // solo, pairwise-all, pairwise-clean, mutation, targeted
	Assign map[string]int

	// Targeted cases carry raw overrides instead of model assignments.
	RawYAML map[string]any    // dotted path -> value (nil value deletes)
	RawEnv  map[string]string // env name -> value ("\x00" deletes)

	// Filled by Materialize.
	Dir       string
	Doc       map[string]any
	Env       map[string]string
	Args      []string
	Stdin     string
	Canaries  map[string]string // marker -> name
	Ports     [2]int
	Startable bool
}

// Template is the initialised baseline directory (admin init, generate-secrets,
// encryption init, migrate) that every case starts from.
type Template struct {
	Dir        string
	Doc        map[string]any
	Passphrase string
}

// LoadTemplate reads the baseline written into dir.
func LoadTemplate(dir string) (*Template, error) {
	b, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	pw, err := os.ReadFile(filepath.Join(dir, "secrets", "master_password"))
	if err != nil {
		return nil, err
	}
	return &Template{Dir: dir, Doc: doc, Passphrase: strings.TrimRight(string(pw), "\r\n")}, nil
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func canaryFor(caseID, name string) string {
	h := sha1.Sum([]byte(caseID + "/" + name)) // #nosec G401
	return "cnry_" + name + "_" + hex.EncodeToString(h[:6])
}

var tokenRE = regexp.MustCompile(`\$(PORT2|PORT|BASEPW|BASEFILE:[a-z_]+|FX:[a-z]+|CANARY:[a-z0-9_]+)`)

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopy(e)
		}
		return s
	}
	return v
}

func setPath(doc map[string]any, path string, val any, del bool) {
	segs := strings.Split(path, ".")
	cur := doc
	for i, s := range segs {
		if i == len(segs)-1 {
			if del {
				delete(cur, s)
			} else {
				cur[s] = val
			}
			return
		}
		next, ok := cur[s].(map[string]any)
		if !ok {
			if del {
				return
			}
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
}

// GetPath returns the value at a dotted path of a generic document.
func GetPath(doc map[string]any, path string) (any, bool) {
	var cur any = doc
	for _, s := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[s]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// Materialize writes the case into a fresh directory under root and fills the
// rendered fields. light copies only the small key/cert/secret directories (enough
// for Load and Validate); otherwise the whole baseline, database included, is copied.
func (c *Case) Materialize(m *Model, t *Template, root string, light bool) error {
	c.Dir = filepath.Join(root, c.ID)
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(t.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == "keyorix.yaml" {
			continue
		}
		if light && !(e.Name() == "certs" || e.Name() == "keys" || e.Name() == "secrets") {
			continue
		}
		if err := copyTree(filepath.Join(t.Dir, e.Name()), filepath.Join(c.Dir, e.Name())); err != nil {
			return err
		}
	}
	c.Ports = [2]int{freePort(), freePort()}
	c.Canaries = map[string]string{}
	c.Startable = true
	c.Doc = deepCopy(t.Doc).(map[string]any)
	c.Env = map[string]string{
		"KEYORIX_CONFIG_PATH":          filepath.Join(c.Dir, "keyorix.yaml"),
		"KEYORIX_MASTER_PASSWORD_FILE": filepath.Join(c.Dir, "secrets", "master_password"),
	}
	c.Args = nil
	c.Stdin = ""

	ids := make([]string, 0, len(c.Assign))
	for id := range c.Assign {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if p := m.Param(id); p != nil && c.Assign[id] < len(p.Values) {
			wp := p.Values[c.Assign[id]].With
			keys := make([]string, 0, len(wp))
			for k := range wp {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				setPath(c.Doc, k, c.resolve(deepCopy(wp[k])), false)
			}
		}
	}
	for _, id := range ids {
		p := m.Param(id)
		if p == nil {
			return fmt.Errorf("case %s: unknown param %q", c.ID, id)
		}
		v := p.Values[c.Assign[id]]
		if !v.CanStart() {
			c.Startable = false
		}
		switch p.Kind {
		case KindYAML:
			if v.Absent {
				setPath(c.Doc, p.Path, nil, true)
			} else {
				setPath(c.Doc, p.Path, c.resolve(deepCopy(v.V)), false)
			}
		case KindEnv:
			if v.Absent {
				delete(c.Env, p.Path)
			} else {
				c.Env[p.Path] = fmt.Sprint(c.resolve(v.V))
			}
		case KindArg:
			if v.Absent {
				break
			}
			if b, ok := v.V.(bool); ok && b {
				c.Args = append(c.Args, p.Path)
				if p.Path == "--passphrase-stdin" {
					c.Stdin = t.Passphrase + "\n"
				}
			} else {
				c.Args = append(c.Args, p.Path+"="+fmt.Sprint(c.resolve(v.V)))
			}
		}
	}
	for path, val := range c.RawYAML {
		if val == nil {
			setPath(c.Doc, path, nil, true)
		} else {
			setPath(c.Doc, path, c.resolve(deepCopy(val)), false)
		}
	}
	for k, val := range c.RawEnv {
		if val == "\x00" {
			delete(c.Env, k)
		} else {
			c.Env[k] = fmt.Sprint(c.resolve(val))
		}
	}
	for _, a := range c.Args {
		_ = a
	}
	c.materialiseFixtures()
	out, err := yaml.Marshal(c.Doc)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Dir, "keyorix.yaml"), out, 0o600)
}

func (c *Case) resolve(v any) any {
	switch x := v.(type) {
	case string:
		return tokenRE.ReplaceAllStringFunc(x, func(tok string) string {
			switch {
			case tok == "$PORT":
				return strconv.Itoa(c.Ports[0])
			case tok == "$PORT2":
				return strconv.Itoa(c.Ports[1])
			case tok == "$BASEPW":
				return c.basePW()
			case strings.HasPrefix(tok, "$BASEFILE:"):
				return filepath.Join(c.Dir, "secrets", strings.TrimPrefix(tok, "$BASEFILE:"))
			case strings.HasPrefix(tok, "$FX:"):
				return filepath.Join(c.Dir, "fx", strings.TrimPrefix(tok, "$FX:"))
			case strings.HasPrefix(tok, "$CANARY:"):
				name := strings.TrimPrefix(tok, "$CANARY:")
				val := canaryFor(c.ID, name)
				c.Canaries[val] = name
				return val
			}
			return tok
		})
	case []any:
		for i := range x {
			x[i] = c.resolve(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = c.resolve(x[k])
		}
		return x
	}
	return v
}

func (c *Case) basePW() string {
	b, err := os.ReadFile(filepath.Join(c.Dir, "secrets", "master_password"))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\r\n")
}

// materialiseFixtures creates the fixture files a case refers to (after placeholder
// resolution the paths are absolute under <dir>/fx).
func (c *Case) materialiseFixtures() {
	fx := filepath.Join(c.Dir, "fx")
	_ = os.MkdirAll(fx, 0o700)
	_ = os.WriteFile(filepath.Join(fx, "empty"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(fx, "world"), []byte("world-readable-secret-file\n"), 0o644) // #nosec G306 -- deliberate fixture
	_ = os.Chmod(filepath.Join(fx, "world"), 0o644)                                             // #nosec G302
	_ = os.MkdirAll(filepath.Join(fx, "dir"), 0o700)
	_ = os.WriteFile(filepath.Join(fx, "garbage"), []byte("this is not a PEM block\n"), 0o600)
	_ = os.WriteFile(filepath.Join(fx, "token"), []byte("fixture-token-value-0123456789\n"), 0o600)
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
}

// lookup returns the effective written value of a path for conflict evaluation:
// YAML dotted paths from the document, env names from the environment, flag names from
// the arguments.
func (c *Case) lookup(path string) (any, bool) {
	if strings.HasSuffix(path, "#haspw") {
		v, ok := GetPath(c.Doc, strings.TrimSuffix(path, "#haspw"))
		s, _ := v.(string)
		return ok && (strings.Contains(s, "password=") || regexp.MustCompile(`://[^/@:]+:[^@]+@`).MatchString(s)), true
	}
	if strings.HasPrefix(path, "KEYORIX_") {
		v, ok := c.Env[path]
		return v, ok
	}
	if strings.HasPrefix(path, "--") {
		for _, a := range c.Args {
			if a == path || strings.HasPrefix(a, path+"=") {
				return true, true
			}
		}
		return nil, false
	}
	return GetPath(c.Doc, path)
}

func matchOne(want any, got any, present bool) bool {
	w, _ := want.(string)
	switch {
	case w == "$absent":
		return !present
	case w == "$empty":
		return present && fmt.Sprint(got) == ""
	case w == "$nonempty":
		return present && fmt.Sprint(got) != "" && got != nil
	}
	return present && fmt.Sprint(got) == fmt.Sprint(want)
}

// TriggeredConflicts returns the conflicts of the model that the case's rendered
// configuration triggers.
func (m *Model) TriggeredConflicts(c *Case) []Conflict {
	var out []Conflict
	for _, cf := range m.Conflicts {
		all := true
		for path, wants := range cf.When {
			got, present := c.lookup(path)
			hit := false
			for _, w := range wants {
				if matchOne(w, got, present) {
					hit = true
					break
				}
			}
			if !hit {
				all = false
				break
			}
		}
		if all {
			out = append(out, cf)
		}
	}
	return out
}

// Faults lists the model options in the case that the model expects to be refused:
// invalid values. Used to decide whether a refusal is explained.
func (m *Model) Faults(c *Case) []*Param {
	var out []*Param
	ids := make([]string, 0, len(c.Assign))
	for id := range c.Assign {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := m.Param(id)
		if p.Values[c.Assign[id]].Class == ClassInvalid {
			out = append(out, p)
		}
	}
	return out
}
