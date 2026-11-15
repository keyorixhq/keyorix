package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postureYAMLWritingPath builds a minimal YAML document that writes path (alias
// table spelling: a "seg[]" segment is a sequence with one element) to true.
func postureYAMLWritingPath(path string) string {
	var b strings.Builder
	indent := ""
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		name := strings.TrimSuffix(seg, "[]")
		switch {
		case i == len(segs)-1:
			fmt.Fprintf(&b, "%s%s: true\n", indent, name)
		case strings.HasSuffix(seg, "[]"):
			fmt.Fprintf(&b, "%s%s:\n%s  - name: x\n", indent, name, indent)
			indent += "    "
		default:
			fmt.Fprintf(&b, "%s%s:\n", indent, name)
			indent += "  "
		}
	}
	return b.String()
}

// TestPostureOrigin_EveryDeprecatedAliasReadsAsExplicit is the #2925 guard at the
// posture's own seam: for EVERY (old, new) pair Load still rewrites (derived from
// config.DeprecatedSettingAliasPaths, the table itself, not a hand list), a config
// FILE that writes only the old name must make writesAnyOf true for the registry
// entry that owns the new name. writesAnyOf is what labels a deviation explicit
// rather than shipped-default, so a miss here is the mislabel the issue describes.
// A pair no registry entry owns fails too: the alias would then be invisible to
// the posture report altogether.
func TestPostureOrigin_EveryDeprecatedAliasReadsAsExplicit(t *testing.T) {
	pairs := config.DeprecatedSettingAliasPaths()
	require.NotEmpty(t, pairs, "no deprecated alias exists: this guard checks nothing")
	for _, pair := range pairs {
		oldPath, newPath := pair[0], pair[1]
		t.Run(oldPath, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "keyorix.yaml")
			require.NoError(t, os.WriteFile(cfgPath, []byte(postureYAMLWritingPath(oldPath)), 0o600))
			explicit, err := config.ExplicitlySetPaths(cfgPath)
			require.NoError(t, err)

			want := strings.ReplaceAll(newPath, "[]", "")
			owners := 0
			for _, s := range config.InsecureSettingsRegistry {
				owned := false
				for _, p := range s.SourcePaths {
					owned = owned || p == want
				}
				if !owned {
					continue
				}
				owners++
				assert.True(t, writesAnyOf(explicit, s.SourcePaths),
					"%s: a file writing only the deprecated %q must label %s explicit, not shipped-default", s.Name, oldPath, want)
			}
			assert.NotZero(t, owners, "no registry entry names %q in its SourcePaths, so the posture report cannot see the alias %q", want, oldPath)
		})
	}
}

// #2925, the other two arms of the table: for every deprecated alias, a file that
// writes NOTHING is not explicit (the shipped default), and a file that writes BOTH
// the old and the new spelling is explicit.
func TestPostureOrigin_DeprecatedAliasSilentAndBothArms(t *testing.T) {
	for _, pair := range config.DeprecatedSettingAliasPaths() {
		oldPath, newPath := pair[0], pair[1]
		t.Run(oldPath, func(t *testing.T) {
			want := strings.ReplaceAll(newPath, "[]", "")
			var owner *config.InsecureSetting
			for i := range config.InsecureSettingsRegistry {
				for _, p := range config.InsecureSettingsRegistry[i].SourcePaths {
					if p == want {
						owner = &config.InsecureSettingsRegistry[i]
					}
				}
			}
			require.NotNil(t, owner, "no registry entry owns %q", want)

			write := func(doc string) map[string]bool {
				cfgPath := filepath.Join(t.TempDir(), "keyorix.yaml")
				require.NoError(t, os.WriteFile(cfgPath, []byte(doc), 0o600))
				explicit, err := config.ExplicitlySetPaths(cfgPath)
				require.NoError(t, err)
				return explicit
			}
			assert.False(t, writesAnyOf(write("# nothing\n"), owner.SourcePaths),
				"%s: a file that writes nothing must read as shipped default", owner.Name)
			// Concatenated documents repeat top-level keys; ExplicitlySetPaths
			// reads the file as a yaml.Node, which keeps both.
			bothDoc := postureYAMLWritingPath(oldPath) + postureYAMLWritingPath(newPath)
			assert.True(t, writesAnyOf(write(bothDoc), owner.SourcePaths),
				"%s: a file writing both spellings is explicit", owner.Name)
		})
	}
}
