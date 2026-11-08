package configspace

import (
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// accessors maps a secret to the YAML key that can also carry it and the accessor that
// returns the effective value (I5: the environment variable wins over the file value).
var accessors = []struct {
	Env, YAML string
	Get       func(*config.Config) string
}{
	{"KEYORIX_SIEM_TOKEN", "audit.siem.token", func(c *config.Config) string { return c.Audit.SIEM.GetToken() }},
	{"KEYORIX_SCIM_TOKEN", "scim.token", func(c *config.Config) string { return c.SCIM.GetToken() }},
	{"KEYORIX_DB_PASSWORD", "storage.database.password", func(c *config.Config) string {
		// Read through the production resolver: the password is only ever handed to the driver as parsed config.
		cc, err := config.ResolvePostgresConnConfig(&c.Storage.Database)
		if err != nil {
			return ""
		}
		return cc.Password
	}},
}

// PrecedenceCases builds the targeted I5 cases for the secret sources.
func PrecedenceCases() []*Case {
	var out []*Case
	names := append([]string(nil), config.SecretEnvVars...)
	sort.Strings(names)
	for _, n := range names {
		if n == "KEYORIX_MASTER_PASSWORD" {
			continue // exercised through the model's env/flag parameters
		}
		out = append(out,
			&Case{ID: "prec-both-" + n, Kind: "targeted", RawEnv: map[string]string{n: "$CANARY:both", n + "_FILE": "$FX:token"}},
			&Case{ID: "prec-badfile-" + n, Kind: "targeted", RawEnv: map[string]string{n: "$CANARY:fallback", n + "_FILE": "$FX:missing"}},
			&Case{ID: "prec-emptyfile-" + n, Kind: "targeted", RawEnv: map[string]string{n + "_FILE": "$FX:empty"}},
			&Case{ID: "prec-dirfile-" + n, Kind: "targeted", RawEnv: map[string]string{n + "_FILE": "$FX:dir"}},
		)
	}
	for _, a := range accessors {
		out = append(out, &Case{
			ID: "prec-envwins-" + a.Env, Kind: "targeted",
			RawEnv:  map[string]string{a.Env: "$CANARY:envvalue"},
			RawYAML: map[string]any{a.YAML: "$CANARY:yamlvalue"},
		})
	}
	// DSN carrying a password together with a password source
	out = append(out,
		&Case{ID: "prec-dsnpw-env", Kind: "targeted",
			RawYAML: map[string]any{"storage.type": "postgres", "storage.database.path": nil,
				"storage.database.dsn": "host=localhost user=k dbname=k password=$CANARY:dsnpw sslmode=disable"},
			RawEnv: map[string]string{"KEYORIX_DB_PASSWORD": "$CANARY:envpw"}}, // #nosec G101 -- synthetic canary placeholder, not a credential
	)
	return out
}

// CheckPrecedence evaluates the I5 rules on a targeted case.
func CheckPrecedence(c *Case, r InProcResult) []Finding {
	var fs []Finding
	add := func(sev, key, title, detail string) {
		fs = append(fs, Finding{Inv: "I5", Sev: sev, Stage: "inproc", Case: c.ID, Key: key, Title: title, Detail: detail})
	}
	switch {
	case strings.HasPrefix(c.ID, "prec-both-"), strings.HasPrefix(c.ID, "prec-badfile-"),
		strings.HasPrefix(c.ID, "prec-emptyfile-"), strings.HasPrefix(c.ID, "prec-dirfile-"):
		n := c.ID[strings.Index(c.ID[len("prec-"):], "-")+len("prec-")+1:]
		if r.Panic != "" {
			add("S3", "prec-panic:"+c.ID, "panic", r.Panic)
			return fs
		}
		if r.Accepted {
			add("S2", "prec-accepted:"+c.ID, "bad secret source accepted ("+n+")", "Load and Validate accepted the combination")
		} else if !strings.Contains(r.Err, n) {
			add("S3", "prec-unnamed:"+c.ID, "refusal does not name the variable ("+n+")", r.Err)
		}
	case strings.HasPrefix(c.ID, "prec-envwins-"):
		if r.Cfg == nil {
			return fs
		}
		for _, a := range accessors {
			if "prec-envwins-"+a.Env == c.ID {
				want := ""
				for val, name := range c.Canaries {
					if name == "envvalue" {
						want = val
					}
				}
				if got := r.Acc[a.Env]; got != want {
					add("S2", "prec-envloses:"+a.Env, "environment variable does not win over the file value ("+a.Env+")", "effective value differs from the environment value")
				}
			}
		}
	case c.ID == "prec-dsnpw-env":
		if r.Accepted {
			add("S2", "prec-dsnpw-accepted", "DSN password plus password source accepted", "documented as refused at startup")
		}
	}
	return fs
}

// aliasCase renders one alias spelling (old or new dotted path, which may cross "[]").
func aliasYAML(path string, val any) map[string]any {
	segs := strings.Split(path, ".")
	for i, s := range segs {
		if before, ok := strings.CutSuffix(s, "[]"); ok {
			head := strings.Join(append(append([]string{}, segs[:i]...), before), ".")
			elem := map[string]any{}
			if i+1 < len(segs) {
				cur := elem
				for j := i + 1; j < len(segs); j++ {
					if j == len(segs)-1 {
						cur[segs[j]] = val
					} else {
						nx := map[string]any{}
						cur[segs[j]] = nx
						cur = nx
					}
				}
			}
			elem["name"] = "csprov"
			return map[string]any{head: []any{elem}}
		}
	}
	return map[string]any{path: val}
}

// AliasCases builds the I5 alias differential cases from the code's own alias table.
func AliasCases() []*Case {
	out := []*Case{{ID: "alias-base", Kind: "targeted", RawYAML: map[string]any{}}}
	for i, pair := range config.DeprecatedSettingAliasPaths() {
		old, nw := pair[0], pair[1]
		mk := func(tag string, oldv, newv any) *Case {
			raw := map[string]any{}
			for _, p := range []string{old, nw} {
				if !strings.Contains(p, "[]") {
					raw[p] = nil // drop the baseline's own spelling of the key
				}
			}
			if oldv != nil {
				maps.Copy(raw, aliasYAML(old, oldv))
			}
			if newv != nil {
				for k, v := range aliasYAML(nw, newv) {
					// merge when both spellings live in one list element
					if ex, ok := raw[k].([]any); ok {
						if nm, ok := v.([]any); ok {
							maps.Copy(ex[0].(map[string]any), nm[0].(map[string]any))
							continue
						}
					}
					raw[k] = v
				}
			}
			return &Case{ID: fmt.Sprintf("alias-%02d-%s", i, tag), Kind: "targeted", RawYAML: raw}
		}
		out = append(out, mk("old", true, nil), mk("new", nil, true), mk("oldT-newF", true, false), mk("oldF-newT", false, true))
	}
	return out
}

func sameStrings(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "|") == strings.Join(y, "|")
}

// CheckAliases compares the alias cases pairwise. results is keyed by case id.
func CheckAliases(results map[string]InProcResult) []Finding {
	var fs []Finding
	pairs := config.DeprecatedSettingAliasPaths()
	base := results["alias-base"].Registry
	minus := func(a []string) []string {
		var out []string
		for _, x := range a {
			found := false
			for _, b := range base {
				if b == x {
					found = true
				}
			}
			if !found {
				out = append(out, x)
			}
		}
		return out
	}
	for i, pr := range pairs {
		id := func(t string) string { return fmt.Sprintf("alias-%02d-%s", i, t) }
		o, n := results[id("old")], results[id("new")]
		add := func(sev, key, title, detail string) {
			fs = append(fs, Finding{Inv: "I5", Sev: sev, Stage: "inproc", Case: id("old"), Key: key, Title: title, Detail: detail})
		}
		if o.Panic != "" || n.Panic != "" {
			add("S3", "alias-panic:"+pr[0], "panic loading deprecated alias "+pr[0], o.Panic+n.Panic)
			continue
		}
		if o.LoadFailed != n.LoadFailed {
			add("S2", "alias-load-diff:"+pr[0], "deprecated alias and its replacement load differently ("+pr[0]+")", "old: "+o.Err+" | new: "+n.Err)
			continue
		}
		if !o.LoadFailed && !sameStrings(minus(o.Registry), minus(n.Registry)) {
			add("S2", "alias-effect-diff:"+pr[0], "deprecated alias and its replacement differ in effect ("+pr[0]+")", fmt.Sprint(minus(o.Registry))+" vs "+fmt.Sprint(minus(n.Registry)))
		}
		if len(o.Warnings) == 0 && !o.LoadFailed {
			add("S3", "alias-nowarn:"+pr[0], "deprecated alias used without a deprecation warning ("+pr[0]+")", "")
		}
		of, nt := results[id("oldF-newT")], results[id("oldT-newF")]
		if !of.LoadFailed && !nt.LoadFailed {
			// stricter-wins check: weaker means more registry entries in effect
			if len(minus(of.Registry)) > 0 {
				add("S4", "alias-conflict-weaker:"+pr[0], "alias conflict resolves to the weaker value: the replacement key wins even when it is the weakening one ("+pr[0]+")", "documented in resolveDeprecatedAliases: the replacement wins")
			}
			if len(minus(nt.Registry)) > 0 {
				add("S2", "alias-conflict-weaker2:"+pr[0], "alias conflict: deprecated weakening key beat the replacement ("+pr[0]+")", fmt.Sprint(minus(nt.Registry)))
			}
		}
	}
	return fs
}
