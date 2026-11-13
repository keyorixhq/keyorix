package configcompat

import (
	"embed"
	"io/fs"
	"sort"
)

// Revs names the earlier releases this harness treats as the "old" side of the
// differential, newest-last. Picked by the evidence in README.md §1: v0.95.3 is
// the last release before the ADR-112 insecure_ rename (#2899, first in
// v0.96.0), so the pair (v0.95.3, v0.96.0) brackets the single largest
// config-compatibility event, and v0.60.0/v0.80.0 spread the sample across the
// old-name era.
var Revs = []string{"v0.60.0", "v0.80.0", "v0.95.3", "v0.96.0"}

//go:embed testdata/oldconfigs
var oldConfigsFS embed.FS

// SeedConfigs returns the real, shipped example config files pulled from the
// old tags in Revs (the ground-truth "valid at the old rev" corpus), keyed by
// "<rev>__<file>". These are the fuzz seeds.
func SeedConfigs() map[string][]byte {
	out := map[string][]byte{}
	_ = fs.WalkDir(oldConfigsFS, "testdata/oldconfigs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, rerr := oldConfigsFS.ReadFile(p)
		if rerr != nil {
			return nil
		}
		name := d.Name()
		out[name] = b
		return nil
	})
	return out
}

// seedNamesSorted returns the seed names in a deterministic order.
func seedNamesSorted(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
