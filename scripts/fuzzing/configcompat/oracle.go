package configcompat

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/scripts/fuzzing/configspace"
)

// Finding is one oracle verdict. Classification (VULNERABILITY / DEFECT /
// EXPECTED-DIFFERENCE / ...) is a human judgement made in the report, never by
// the harness; the harness only reports the raw, minimisable fact.
type Finding struct {
	Invariant string // "I1", "I2", "I3"
	Reason    string
	Key       string
	Detail    string
}

func (f Finding) String() string {
	return f.Invariant + ": " + f.Reason + " [" + f.Key + "] " + f.Detail
}

// LoadResult is the outcome of loading one config byte slice.
type LoadResult struct {
	Verdict  string // "" = accepted; otherwise "load: ..." / "validate: ..."
	Cfg      *config.Config
	Warnings []string
	Panicked bool
}

// LoadFunc loads a config byte slice. The real implementation is (*Env).Load;
// planted tests inject a defective wrapper to prove an oracle is not vacuous.
type LoadFunc func(data []byte) LoadResult

// Env holds the per-run scratch state (a temp dir for the config file).
type Env struct {
	dir  string
	file string
}

// NewEnv makes an Env backed by dir (must exist).
func NewEnv(dir string) *Env {
	return &Env{dir: dir, file: filepath.Join(dir, "configcompat.yaml")}
}

// Load writes data to the Env's config file and runs the REAL config.Load +
// Validate, recovering any panic. It mirrors the configspace harness: an empty
// storage type defaults to "local" so Validate has something to check.
func (e *Env) Load(data []byte) (res LoadResult) {
	defer func() {
		if r := recover(); r != nil {
			res.Panicked = true
			res.Verdict = "panic"
		}
	}()
	if err := os.WriteFile(e.file, data, 0o600); err != nil {
		res.Verdict = "write: " + err.Error()
		return res
	}
	c, err := config.Load(e.file)
	if err != nil {
		res.Verdict = "load: " + err.Error()
		return res
	}
	res.Cfg = c
	res.Warnings = c.DeprecatedSettingWarnings
	if c.Storage.Type == "" {
		c.Storage.Type = "local"
	}
	if verr := c.Validate(); verr != nil {
		res.Verdict = "validate: " + verr.Error()
	}
	return res
}

// knownTopLevelKeys are the YAML keys config.Config can decode at the top
// level, derived from the configspace model so an unknown-key probe never
// collides with a real field.
func knownTopLevelKeys(m *configspace.Model) map[string]bool {
	keys := map[string]bool{}
	for _, p := range m.Params {
		if p.Kind != configspace.KindYAML {
			continue
		}
		top := p.Path
		if i := strings.IndexByte(top, '.'); i >= 0 {
			top = top[:i]
		}
		keys[top] = true
	}
	return keys
}

// CheckI1Robust runs the fail-closed robustness part of I1 on arbitrary data:
// no panic, a deterministic verdict, and no canary VALUE in an error string.
func CheckI1Robust(load LoadFunc, data []byte) []Finding {
	var out []Finding
	r1 := load(data)
	if r1.Panicked {
		out = append(out, Finding{"I1", "Load/Validate panicked", "", trunc(r1.Verdict)})
		return out
	}
	if leaksCanary(r1.Verdict) {
		out = append(out, Finding{"I1", "canary secret value leaked in error", "", trunc(r1.Verdict)})
	}
	r2 := load(data)
	if r2.Verdict != r1.Verdict {
		out = append(out, Finding{"I1", "non-deterministic verdict", "", trunc(r1.Verdict) + " vs " + trunc(r2.Verdict)})
	}
	return out
}

// CheckI1Named runs the named-refusal part of I1: a key HEAD does not recognize
// must be refused with an error that names it. keyName is a fuzzer-supplied
// candidate key; it is only exercised when it is a YAML-safe scalar that is not
// a real top-level field (otherwise the file would legitimately load or fail
// for an unrelated reason).
func CheckI1Named(m *configspace.Model, load LoadFunc, keyName string) []Finding {
	keyName = sanitizeKey(keyName)
	if keyName == "" || knownTopLevelKeys(m)[keyName] {
		return nil
	}
	doc := buildDoc(keyName, true) // "<keyName>: true\n"
	r := load(doc)
	if r.Panicked {
		return []Finding{{"I1", "panic on unknown key", keyName, ""}}
	}
	if !isRefusal(r.Verdict) {
		return []Finding{{"I1", "unknown key accepted, not refused (fail-open)", keyName, trunc(r.Verdict)}}
	}
	if !namesAKey(r.Verdict) || !strings.Contains(r.Verdict, keyName) {
		return []Finding{{"I1", "refusal does not name the offending key", keyName, trunc(r.Verdict)}}
	}
	return nil
}

// ExplicitFunc reports whether a dotted key is explicitly present in the raw
// file. Real = rawHasPath; planted tests inject a stub to prove I2 fires.
type ExplicitFunc func(data []byte, path string) bool

// CheckI2 enforces no-silently-weakened-posture on an accepted config: every
// posture predicate that holds must be either a documented default
// (defaultSet) or explained by an explicit opt-in key present in the raw file.
func CheckI2(m *configspace.Model, r LoadResult, data []byte, defaultSet map[string]bool, explicit ExplicitFunc) []Finding {
	if r.Cfg == nil || isRefusal(r.Verdict) {
		return nil
	}
	holds := map[string]bool{}
	for _, id := range m.PostureHolds(r.Cfg) {
		holds[id] = true
	}
	var out []Finding
	for i := range m.Posture {
		rule := &m.Posture[i]
		if !holds[rule.ID] {
			continue
		}
		if defaultSet[rule.ID] {
			continue // documented, allowlisted default posture
		}
		opted := false
		for _, k := range explainKeys(rule.ID, rule.Explicit) {
			if explicit(data, k) {
				opted = true
				break
			}
		}
		if !opted {
			out = append(out, Finding{"I2", "posture holds with no explicit opt-in and not a documented default (weakened default?)", rule.ID, rule.What})
		}
	}
	return out
}

// CheckI3 enforces deprecated-alias meaning preservation for one alias pair: a
// config written with the old key must load, warn by name, and have a security
// fingerprint identical to the same config written with the new key.
func CheckI3(m *configspace.Model, load LoadFunc, pair AliasPair, value any) []Finding {
	newDoc := buildDoc(pair.New, value)
	oldDoc := buildDoc(pair.Old, value)
	if newDoc == nil || oldDoc == nil {
		return nil
	}
	rNew := load(newDoc)
	rOld := load(oldDoc)
	if rNew.Panicked || rOld.Panicked {
		return []Finding{{"I3", "panic loading alias pair", pair.Old, ""}}
	}
	// We compare the loaded (not necessarily validated) config: Load is where
	// the alias is honoured, and a minimal single-key doc may not validate.
	newOK := rNew.Cfg != nil
	oldOK := rOld.Cfg != nil
	if !newOK && !oldOK {
		return nil // both refused (value invalid for this field) — nothing to compare
	}
	if newOK != oldOK {
		which, verdict := "old", rOld.Verdict
		if !newOK {
			which, verdict = "new", rNew.Verdict
		}
		return []Finding{{"I3", "alias pair diverges on load/refuse (" + which + " refused)", pair.Old, trunc(verdict)}}
	}
	var out []Finding
	fpNew := SecurityFingerprint(m, rNew.Cfg)
	fpOld := SecurityFingerprint(m, rOld.Cfg)
	if fpNew != fpOld {
		out = append(out, Finding{"I3", "deprecated key changed security meaning vs its replacement", pair.Old, "old!=new fingerprint"})
	}
	if !warningNames(rOld.Warnings, pair.Old) {
		out = append(out, Finding{"I3", "deprecated key accepted with no warning naming it (silent)", pair.Old, strings.Join(rOld.Warnings, " | ")})
	}
	return out
}

// warningNames reports whether any warning string mentions the old path.
func warningNames(warnings []string, oldPath string) bool {
	for _, w := range warnings {
		if strings.Contains(w, oldPath) {
			return true
		}
	}
	return false
}

// sanitizeKey turns an arbitrary fuzzer string into a conservative YAML-safe
// mapping key, or "" if nothing usable remains. Keeps only [a-z0-9_] and caps
// the length; prefixes to guarantee it is not a real field.
func sanitizeKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() >= 24 {
			break
		}
	}
	t := b.String()
	if t == "" {
		return ""
	}
	return "cc1u_" + t
}

func trunc(s string) string {
	const n = 200
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
