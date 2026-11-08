package configspace

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Finding is one candidate violation of a rule in RULES.md.
type Finding struct {
	Inv    string `json:"inv"`
	Sev    string `json:"sev"`
	Stage  string `json:"stage"` // inproc | proc | static
	Case   string `json:"case"`
	Key    string `json:"key"` // dedupe key
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// InProcResult is what Load + Validate did with a case.
type InProcResult struct {
	Panic      string
	Err        string
	LoadFailed bool
	Accepted   bool
	Cfg        *config.Config
	Posture    []string
	Registry   []string
	Warnings   []string // Load's deprecated-alias warnings
	Acc        map[string]string
}

// clearEnv removes every KEYORIX_* variable (and the ones the model touches) and
// returns a restore function.
func applyEnv(env map[string]string) func() {
	saved := map[string]*string{}
	save := func(k string) {
		if _, ok := saved[k]; ok {
			return
		}
		if v, ok := os.LookupEnv(k); ok {
			vv := v
			saved[k] = &vv
		} else {
			saved[k] = nil
		}
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "KEYORIX_") || k == "VAULT_TOKEN" {
			save(k)
			_ = os.Unsetenv(k)
		}
	}
	for k, v := range env {
		save(k)
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, v := range saved {
			if v == nil {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, *v)
			}
		}
	}
}

// RunInProc loads and validates the case's configuration inside this process, the way
// server/main.go does (a blank storage.type becomes "local" before Validate).
func RunInProc(m *Model, c *Case) (res InProcResult) {
	restore := applyEnv(c.Env)
	defer restore()
	wd, _ := os.Getwd()
	if err := os.Chdir(c.Dir); err != nil {
		res.Err = "harness: chdir: " + err.Error()
		return res
	}
	defer os.Chdir(wd) //nolint:errcheck
	defer func() {
		if r := recover(); r != nil {
			res.Panic = fmt.Sprint(r)
			res.Accepted = false
		}
	}()
	cfg, err := config.Load(c.Env["KEYORIX_CONFIG_PATH"])
	if err != nil {
		res.LoadFailed = true
		res.Err = err.Error()
		return res
	}
	res.Cfg = cfg
	res.Warnings = cfg.DeprecatedSettingWarnings
	res.Registry, _ = registryInEffect(cfg)
	res.Acc = map[string]string{}
	for _, a := range accessors {
		res.Acc[a.Env] = a.Get(cfg)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if err := cfg.Validate(); err != nil {
		res.Err = err.Error()
		return res
	}
	res.Accepted = true
	res.Posture = m.PostureHolds(cfg)
	return res
}

func secGroup(g string) bool {
	switch g {
	case "security", "session", "tls", "auth", "secrets", "encryption", "audit", "ratelimit", "cors", "alias", "dbtls", "exposure":
		return true
	}
	return false
}

func errNames(errText string, tokens []string) bool {
	e := strings.ToLower(errText)
	for _, t := range tokens {
		if t != "" && strings.Contains(e, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

func lastSeg(p string) string {
	if _, after, ok := strings.CutLast(p, "."); ok {
		return after
	}
	return p
}

// tokensFor returns strings that a refusal caused by the parameter should mention.
func tokensFor(p *Param) []string {
	t := []string{p.Path, lastSeg(p.Path)}
	if p.Kind != KindYAML {
		t = append(t, strings.TrimPrefix(p.Path, "--"))
	}
	return t
}

// CheckInProc applies the in-process invariants to one result.
func CheckInProc(m *Model, c *Case, r InProcResult) []Finding {
	var fs []Finding
	add := func(inv, sev, key, title, detail string) {
		fs = append(fs, Finding{Inv: inv, Sev: sev, Stage: "inproc", Case: c.ID, Key: key, Title: title, Detail: detail})
	}
	if r.Panic != "" {
		add("I1", "S3", "panic:"+c.Kind+":"+firstAssign(c), "panic in Load/Validate", r.Panic)
		return fs
	}
	// I4: canary values in error text.
	for val, name := range c.Canaries {
		if strings.Contains(r.Err, val) {
			add("I4", "S1", "leak-err:"+name, "secret value in Load/Validate error text", "canary "+name+" appears in: "+r.Err)
		}
	}
	faults := m.Faults(c)
	conflicts := m.TriggeredConflicts(c)
	var live []Conflict
	for _, cf := range conflicts {
		if !strings.Contains(cf.Note, "process level only") {
			live = append(live, cf)
		}
	}
	refused := !r.Accepted
	// Command-line flags and the master-passphrase variables are judged by the
	// process stage only (RULES.md amendment 2026-11-07).
	var inFaults []*Param
	for _, p := range faults {
		if p.Kind == KindArg || strings.HasPrefix(p.Path, "KEYORIX_MASTER_PASSWORD") {
			continue
		}
		inFaults = append(inFaults, p)
	}
	if !refused {
		// I2a / I2e: invalid values accepted.
		for _, p := range inFaults {
			v := p.Values[c.Assign[p.ID]]
			if len(faults) > 1 {
				// multi-fault rows: another invalid value may legitimately mask; only
				// single-fault rows can state acceptance as a violation
				break
			}
			sev := "S3"
			if secGroup(p.Group) {
				sev = "S2"
			}
			if v.Fallback != "" {
				add("I2", sev, "invalid-fallback:"+p.ID+":"+fmt.Sprint(v.V), "invalid value silently replaced by a default ("+p.Path+")", "documented in code: "+v.Fallback)
			} else {
				add("I2", sev, "invalid-accepted:"+p.ID+":"+fmt.Sprint(v.V), "invalid value accepted ("+p.Path+")", fmt.Sprintf("value %v", v.V))
			}
		}
		// I2b: conflicts accepted.
		for _, cf := range live {
			add("I2", "S2", "conflict-accepted:"+cf.ID, "contradictory combination accepted ("+cf.ID+")", fmt.Sprint(cf.When))
		}
		fs = append(fs, fidelity(m, c, r)...)
		// I3(a): a posture predicate holds although no weakening key is written.
		for _, id := range r.Posture {
			rule := m.PostureRule(id)
			explicit := false
			for _, k := range rule.Explicit {
				if _, ok := GetPath(c.Doc, k); ok {
					explicit = true
					break
				}
			}
			if !explicit {
				add("I3", "S2", "posture-default:"+id, "insecure posture "+id+" reached with no explicit weakening key", rule.What)
			}
		}
	} else {
		// I2c: the refusal should name an offending option when we know one.
		var tokens []string
		for _, p := range faults {
			tokens = append(tokens, tokensFor(p)...)
		}
		for _, cf := range live {
			tokens = append(tokens, cf.Names...)
		}
		if len(tokens) > 0 && !errNames(r.Err, tokens) {
			add("I2", "S3", "refusal-unnamed:"+firstAssign(c), "refusal does not name the offending option", "error: "+r.Err)
		}
	}
	return fs
}

func firstAssign(c *Case) string {
	ids := make([]string, 0, len(c.Assign))
	for id := range c.Assign {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > 3 {
		ids = ids[:3]
	}
	return strings.Join(ids, "+")
}

// fidelity compares each explicitly written YAML option with the effective value.
func fidelity(m *Model, c *Case, r InProcResult) []Finding {
	var fs []Finding
	for id, vi := range c.Assign {
		p := m.Param(id)
		if p == nil || p.Kind != KindYAML || p.Group == "alias" || m.Normalised(p.Path) {
			continue
		}
		v := p.Values[vi]
		if v.Absent || v.Class == ClassInvalid {
			continue
		}
		if p.Path == "storage.type" && v.V == "" {
			continue // server/main.go maps a blank type to local before Validate
		}
		written, ok := GetPath(c.Doc, p.Path)
		if !ok {
			continue
		}
		eff, ok := lookupEffective(r.Cfg, p.Path)
		if !ok {
			continue
		}
		if !sameValue(written, eff) {
			sev := "S3"
			if secGroup(p.Group) {
				sev = "S2"
			}
			fs = append(fs, Finding{Inv: "I3", Sev: sev, Stage: "inproc", Case: c.ID,
				Key:    "fidelity:" + p.ID + ":" + fmt.Sprint(v.V),
				Title:  "written value differs from effective value (" + p.Path + ")",
				Detail: fmt.Sprintf("written %v, effective %v", written, eff)})
		}
	}
	return fs
}

func sameValue(written, eff any) bool {
	switch e := eff.(type) {
	case []string:
		w, ok := written.([]any)
		if !ok {
			return len(e) == 0 && written == nil
		}
		if len(w) != len(e) {
			return false
		}
		for i := range w {
			if fmt.Sprint(w[i]) != e[i] {
				return false
			}
		}
		return true
	case nil:
		return written == nil
	}
	return reflect.DeepEqual(fmt.Sprint(written), fmt.Sprint(eff))
}
