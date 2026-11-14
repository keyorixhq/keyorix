package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/upgrade-v096 holds the two keyorix.yaml files the v0.96.3 tag's own
// `keyorix-server admin init` writes (default and --dev), byte for byte. They
// carry secrets.chunking and secrets.limits.max_secrets_per_user, which
// ignoredSettingPaths deprecates (#3743).
//
// An operator who upgrades without touching the file must get one of two
// outcomes, never a third: the config loads and every deprecated key it
// carries gets a warning that names the key and says to remove it; or, once a
// release deletes the key, the load fails with an error that names the key
// and says to remove it (not the generic "check its spelling" unknown-key
// error). Today it is the first.
func TestLoad_V096GeneratedConfigsUpgradeWithExactWarnings(t *testing.T) {
	for _, name := range []string{"keyorix.yaml", "keyorix.dev.yaml"} {
		t.Run(name, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("testdata", "upgrade-v096", name))
			require.NoError(t, err)
			deprecated := []string{"secrets.chunking", "secrets.limits.max_secrets_per_user"}

			cfg, err := Load(path)
			if err != nil {
				for _, key := range deprecated {
					if strings.Contains(err.Error(), leafOf(key)) {
						assert.Contains(t, err.Error(), key, "a rejected v0.96 key is named by its full path")
						assert.Contains(t, err.Error(), "remove", "a rejected v0.96 key says what to do")
					}
				}
				t.Fatalf("a v0.96.3 config no longer loads; the error above must name each removed key and say to remove it, then turn this into an expected-error test: %v", err)
			}
			for _, key := range deprecated {
				var hit []string
				for _, w := range cfg.DeprecatedSettingWarnings {
					if strings.Contains(w, `"`+key+`"`) {
						hit = append(hit, w)
					}
				}
				require.Len(t, hit, 1, "exactly one warning for %s, got %q", key, cfg.DeprecatedSettingWarnings)
				assert.Contains(t, hit[0], "remove it")
			}
			assert.Len(t, cfg.DeprecatedSettingWarnings, len(deprecated),
				"no other key in a v0.96.3 generated config is deprecated: %q", cfg.DeprecatedSettingWarnings)
		})
	}
}

func leafOf(path string) string {
	return path[strings.LastIndex(path, ".")+1:]
}
