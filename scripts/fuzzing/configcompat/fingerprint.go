package configcompat

import (
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/scripts/fuzzing/configspace"
)

// SecurityFingerprint is a canonical, comparable summary of every
// security-relevant effective value of a loaded config. Two configs that are
// supposed to mean the same thing (e.g. a deprecated key and its replacement)
// must produce byte-identical fingerprints (I3). It is built from two
// independent sources so neither can hide a divergence the other sees:
//
//   - the config package's OWN insecure-settings registry
//     (config.InsecureSettingsRegistry): name=value for every entry, plus which
//     entries are InEffect. This is the code's own enumeration of what it
//     considers security-weakening.
//   - the configspace posture model's independent predicates
//     (Model.PostureHolds), which deliberately do NOT consult that registry.
//
// Building it never calls Validate and tolerates a panic in any single
// predicate (a panic is itself recorded, so it can't silently drop a dimension).
func SecurityFingerprint(m *configspace.Model, cfg *config.Config) string {
	var lines []string

	// Source 1: the code's own registry.
	func() {
		defer func() {
			if r := recover(); r != nil {
				lines = append(lines, "registry: PANIC")
			}
		}()
		for _, s := range config.InsecureSettingsRegistry {
			val, eff := "?", "?"
			if s.Value != nil {
				val = safeStr(func() string { return s.Value(cfg) })
			}
			if s.InEffect != nil {
				eff = fmt.Sprintf("%v", safeBool(func() bool { return s.InEffect(cfg) }))
			}
			lines = append(lines, fmt.Sprintf("reg\t%s\tvalue=%s\tineffect=%s", s.Name, val, eff))
		}
	}()

	// Source 2: the independent posture predicates.
	func() {
		defer func() {
			if r := recover(); r != nil {
				lines = append(lines, "posture: PANIC")
			}
		}()
		holds := m.PostureHolds(cfg)
		sort.Strings(holds)
		lines = append(lines, "posture\t"+strings.Join(holds, ","))
	}()

	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func safeStr(f func() string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "PANIC"
		}
	}()
	return f()
}

func safeBool(f func() bool) (out bool) {
	defer func() {
		if r := recover(); r != nil {
			out = false
		}
	}()
	return f()
}
