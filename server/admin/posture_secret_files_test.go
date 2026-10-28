package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// SECRETENV-REVIEW-1 F7 (SECRETENV-TAILS-2 item 5): in every warn mode the
// posture report names a too-open *_FILE secret -- variable and path, never the
// contents -- on the deviation line of that warn mode, and the deviation count is
// the same as without the file.

const postureSecretFileContent = "siem-token-content-must-not-appear"

const postureSecretFilesYAML = `
locale:
  language: en
  fallback_language: en
storage:
  type: local
  database:
    path: "{{DIR}}/posture.db"
  encryption:
    enabled: false
security:
  enable_file_permission_check: {{CHECK}}
  insecure_allow_unsafe_file_permissions: {{UNSAFE}}
  require_transport_tls: true
`

func TestPosture_NamesTooOpenSecretFileInEachWarnMode(t *testing.T) {
	modes := []struct {
		name, check, unsafe string
		grace               bool
		collect             func(cfg *config.Config, cfgPath string, report *postureReport)
		wantCategory        string
	}{
		{
			name: "check disabled", check: "false", unsafe: "false",
			collect: func(cfg *config.Config, cfgPath string, r *postureReport) {
				collectFilePermissionPosture(cfg, cfgPath, r)
			},
			wantCategory: "file-permissions",
		},
		{
			name: "insecure_allow_unsafe_file_permissions", check: "true", unsafe: "true",
			collect: func(cfg *config.Config, cfgPath string, r *postureReport) {
				explicit, err := config.ExplicitlySetPaths(cfgPath)
				require.NoError(t, err)
				collectInsecureSettingsPosture(cfg, explicit, r)
			},
			wantCategory: "insecure-setting",
		},
		{
			name: "ADR-112 upgrade grace", check: "true", unsafe: "false", grace: true,
			collect: func(cfg *config.Config, _ string, r *postureReport) {
				collectStartupValidationStatePosture(cfg, true, "", r)
			},
			wantCategory: "grace-period",
		},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			yaml := strings.NewReplacer("{{CHECK}}", m.check, "{{UNSAFE}}", m.unsafe).Replace(postureSecretFilesYAML)
			run := func(t *testing.T, secretFile string) *postureReport {
				t.Setenv("KEYORIX_SIEM_TOKEN", "")
				t.Setenv("KEYORIX_SIEM_TOKEN_FILE", secretFile)
				cfgPath, cfg := writePostureFixture(t, yaml, 0o600)
				if m.grace {
					cfg.Security.EnableFilePermissionCheckImplicitDefault = true
					cfg.Security.EnableFilePermissionCheckUpgradeGrace = true
				}
				report := &postureReport{}
				m.collect(cfg, cfgPath, report)
				return report
			}

			baseline := run(t, "")

			secret := filepath.Join(t.TempDir(), "siem-token")
			require.NoError(t, os.WriteFile(secret, []byte(postureSecretFileContent+"\n"), 0o600))
			require.NoError(t, os.Chmod(secret, 0o644))
			report := run(t, secret)

			assert.Len(t, report.deviations, len(baseline.deviations), "naming the file must not add a deviation")
			var line string
			for _, d := range deviationsIn(report, m.wantCategory) {
				if strings.Contains(d.detail, "KEYORIX_SIEM_TOKEN_FILE") {
					line = d.detail
				}
			}
			require.NotEmpty(t, line, "the %s deviation line must name the too-open secret file; deviations: %+v", m.wantCategory, report.deviations)
			assert.Contains(t, line, `KEYORIX_SIEM_TOKEN_FILE="`+secret+`"`)
			assert.Contains(t, line, "mode 0644 is too open")
			for _, d := range report.deviations {
				assert.NotContains(t, d.detail, postureSecretFileContent, "never the contents")
			}
			named := 0
			for _, d := range report.deviations {
				named += strings.Count(d.detail, "KEYORIX_SIEM_TOKEN_FILE")
			}
			assert.Equal(t, 1, named, "named on exactly one line")
		})
	}
}
