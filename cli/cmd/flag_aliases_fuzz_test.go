package cmd

// LIB-FUZZ-2 target 4a: addScopeFlagAliases (spf13/pflag normalization) on
// command trees it was never written against.
//
// Inventory. The argv of `keyorix ...` is typed by the operator (or a script),
// parsed by cobra/pflag, and rewritten on the way by the normalization function
// addScopeFlagAliases installs: `--project` means `--project-id` on a command that
// only defines the latter, `--env`/`--environment-id` mean `--environment`, and so
// on. A wrong rewrite does not crash anything, it silently sends a value to a
// different flag than the operator named (a project or environment scope for a
// secret operation), which is why this target states the specification and judges
// pflag's resolution of every spelling against it.
//
// Specification (the doc comment of scopeFlagFamilies), checked per command and
// per spelling typed as --<spelling>=<value> on a tree the harness builds:
//   - a flag the command defines under exactly that name is the one set;
//   - otherwise, if the command defines exactly one spelling of that family, that
//     flag is the one set (and is Changed);
//   - otherwise (none, or several spellings defined) the spelling is unknown and
//     parsing fails, setting nothing.
// plus: the normalizer is idempotent, and parsing arbitrary argument soup never
// panics.
//
// The harness does not put a family flag in a persistent flag set of an ancestor:
// that case is a documented precondition, pinned for the real tree by
// TestScopeFlagAliases_NoPersistentFlagInAFamily, not a fuzzed behaviour (an
// ancestor's persistent flag is merged into the leaf only at parse time, after the
// aliases were computed from the leaf's own flags, so the rewrite would capture
// the spelling).

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// withinDeadline runs fn and fails the test if it does not return in time. The cli
// module carries no dependency on the main module's internal/fuzzutil (ADR-108),
// so this is the module-local equivalent of fuzzutil.Guard.
func withinDeadline(t *testing.T, label string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s exceeded 3s", label)
	}
}

func aliasFamilyNames() []string {
	var names []string
	for _, fam := range scopeFlagFamilies {
		names = append(names, fam...)
	}
	return names
}

type aliasTree struct {
	root   *cobra.Command
	leaves []*cobra.Command
	masks  []uint8 // flag names each leaf defines itself, bit i = aliasFamilyNames()[i]
}

// buildAliasTree builds root -> {a, b, group -> c}: leaf a, b and c define the
// family flags selected by their mask byte, group itself defines none.
func buildAliasTree(masks [3]uint8, aliases bool) *aliasTree {
	names := aliasFamilyNames()
	mk := func(use string, mask uint8) *cobra.Command {
		c := &cobra.Command{Use: use, Run: func(*cobra.Command, []string) {}, SilenceErrors: true, SilenceUsage: true}
		for i, n := range names {
			if mask&(1<<i) != 0 {
				c.Flags().String(n, "", n)
			}
		}
		return c
	}
	root := &cobra.Command{Use: "root", SilenceErrors: true, SilenceUsage: true}
	a, b, c := mk("a", masks[0]), mk("b", masks[1]), mk("c", masks[2])
	group := &cobra.Command{Use: "group", SilenceErrors: true, SilenceUsage: true}
	group.AddCommand(c)
	root.AddCommand(a, b, group)
	if aliases {
		addScopeFlagAliases(root)
	}
	return &aliasTree{root: root, leaves: []*cobra.Command{a, b, c}, masks: masks[:]}
}

// expectedTarget is the specification: which flag the spelling resolves to on a
// leaf defining the names in mask, or "" for unknown.
func expectedTarget(mask uint8, spelling string) string {
	names := aliasFamilyNames()
	if i := slices.Index(names, spelling); i >= 0 && mask&(1<<i) != 0 {
		return spelling
	}
	for _, fam := range scopeFlagFamilies {
		if !slices.Contains(fam, spelling) {
			continue
		}
		var defined []string
		for _, n := range fam {
			if mask&(1<<slices.Index(names, n)) != 0 {
				defined = append(defined, n)
			}
		}
		if len(defined) == 1 {
			return defined[0]
		}
	}
	return ""
}

// resolveSpelling parses --<spelling>=<value> on leaf and reports which flags ended
// up Changed (name -> value) and the parse error.
func resolveSpelling(leaf *cobra.Command, spelling, value string) (map[string]string, error) {
	err := leaf.ParseFlags([]string{"--" + spelling + "=" + value})
	changed := map[string]string{}
	leaf.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			changed[f.Name] = f.Value.String()
		}
	})
	return changed, err
}

// checkAliasResolution is the oracle for one (tree, leaf, spelling, value).
func checkAliasResolution(leaf *cobra.Command, mask uint8, spelling, value string) error {
	want := expectedTarget(mask, spelling)
	changed, err := resolveSpelling(leaf, spelling, value)
	switch {
	case want == "":
		if err == nil || len(changed) != 0 {
			return fmt.Errorf("--%s resolves to %v (err %v) on a command where it must be unknown", spelling, changed, err)
		}
	case err != nil:
		return fmt.Errorf("--%s refused (%v) but should set --%s", spelling, err, want)
	case len(changed) != 1 || changed[want] != value:
		return fmt.Errorf("--%s=%q set %v, want exactly --%s", spelling, value, changed, want)
	}
	// Idempotent: normalizing a normalized name changes nothing.
	if fn := leaf.Flags().GetNormalizeFunc(); fn != nil {
		for _, n := range aliasFamilyNames() {
			once := fn(leaf.Flags(), n)
			if twice := fn(leaf.Flags(), string(once)); twice != once {
				return fmt.Errorf("normalizing %q is not idempotent: %q then %q", n, once, twice)
			}
		}
	}
	return nil
}

func FuzzScopeFlagAliases(f *testing.F) {
	for _, m := range [][3]uint8{
		{1, 2, 4}, {0b00001, 0b00010, 0b00011}, {0b01000, 0b10000, 0b11000}, {0b00100, 0b01100, 0b11100},
		{0b11111, 0, 0b10101}, {0b00010, 0b01000, 0b10000},
	} {
		for i := range aliasFamilyNames() {
			f.Add(m[0], m[1], m[2], uint8(i), "payments", uint8(i), "x\x00y --z=1")
		}
	}
	f.Fuzz(func(t *testing.T, m0, m1, m2, leafIdx uint8, value string, spellingIdx uint8, soup string) {
		masks := [3]uint8{m0 & 0x1f, m1 & 0x1f, m2 & 0x1f}
		names := aliasFamilyNames()
		spelling := names[int(spellingIdx)%len(names)]
		withinDeadline(t, "alias resolution", func() {
			// A fresh tree per check: pflag state (Changed, values) is per parse.
			tree := buildAliasTree(masks, true)
			i := int(leafIdx) % len(tree.leaves)
			if err := checkAliasResolution(tree.leaves[i], masks[i], spelling, value); err != nil {
				t.Errorf("masks %05b/%05b/%05b leaf %d: %v", masks[0], masks[1], masks[2], i, err)
			}
			// Argument soup: never a panic, whatever pflag makes of it.
			soupTree := buildAliasTree(masks, true)
			_ = soupTree.leaves[i].ParseFlags(strings.Split(soup, "\x00"))
			_ = soupTree.leaves[i].ParseFlags(strings.Fields(soup))
		})
	})
}

// TestScopeFlagAliases_NoPersistentFlagInAFamily pins the fuzz target's precondition
// for the real command tree: no command's persistent flag set holds a family spelling.
func TestScopeFlagAliases_NoPersistentFlagInAFamily(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
			if slices.Contains(aliasFamilyNames(), f.Name) {
				t.Errorf("%s defines persistent flag --%s: addScopeFlagAliases computes aliases before it is merged into the leaves", c.CommandPath(), f.Name)
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(rootCmd)
}

// TestScopeFlagAliasOracle_RedProof plants broken normalizers and requires the
// oracle to name each one: a wrong target, a swallowed spelling and a
// non-idempotent rewrite. The unplanted tree must pass for every spelling.
func TestScopeFlagAliasOracle_RedProof(t *testing.T) {
	names := aliasFamilyNames()
	for _, masks := range [][3]uint8{{1, 2, 4}, {0b11, 0b00100, 0b11000}, {0b10100, 0b01010, 0}} {
		for _, spelling := range names {
			tree := buildAliasTree(masks, true)
			for i, leaf := range tree.leaves {
				if err := checkAliasResolution(leaf, masks[i], spelling, "v"); err != nil {
					t.Errorf("oracle rejects the real aliasing (masks %v leaf %d --%s): %v", masks, i, spelling, err)
				}
			}
		}
	}
	// Planted faults, installed over the real normalizer on a leaf that defines
	// only "project-id" (so --project must resolve to it).
	plant := func(fn func(string) string) error {
		tree := buildAliasTree([3]uint8{0b00010, 0, 0}, true)
		leaf := tree.leaves[0]
		leaf.Flags().SetNormalizeFunc(func(_ *pflag.FlagSet, n string) pflag.NormalizedName { return pflag.NormalizedName(fn(n)) })
		return checkAliasResolution(leaf, 0b00010, "project", "v")
	}
	for name, fn := range map[string]func(string) string{
		"identity (no aliasing at all)": func(n string) string { return n },
		"alias to the wrong family":     func(n string) string { return strings.Replace(n, "project", "environment", 1) },
		"rewrites the defined flag too": func(n string) string {
			return strings.TrimSuffix(strings.Replace(n, "project", "project-id", 1), "-id-id") + "-id"
		},
	} {
		if plant(fn) == nil {
			t.Errorf("oracle missed planted fault: %s", name)
		}
	}
}
