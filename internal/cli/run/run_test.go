package run

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterSensitiveEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/dev",
		"KEYORIX_TOKEN=super-secret-token",
		"KEYORIX_API_KEY=kx_api_abc",
		"KEYORIX_REMOTE_API_KEY=kx_remote_abc",
		"KEYORIX_BOOTSTRAP_TOKEN=boot-tok",
		"KEYORIX_PASSWORD=hunter2",
		"KEYORIX_MASTER_PASSWORD=hunter3",
		"KEYORIX_TARGET_KEK=base64kek",
		"KEYORIX_DYNAMIC_ADMIN_DSN=postgres://u:p@h/db",
		"KEYORIX_PROJECT=payments", // not a credential — must survive
		"KEYORIX_SERVER=https://x", // not a credential — must survive
		"KEYORIX_ENV=production",   // not a credential — must survive
	}

	out := filterSensitiveEnv(in)

	t.Run("strips every Keyorix credential var", func(t *testing.T) {
		for _, sensitive := range []string{
			"KEYORIX_TOKEN=super-secret-token",
			"KEYORIX_API_KEY=kx_api_abc",
			"KEYORIX_REMOTE_API_KEY=kx_remote_abc",
			"KEYORIX_BOOTSTRAP_TOKEN=boot-tok",
			"KEYORIX_PASSWORD=hunter2",
			"KEYORIX_MASTER_PASSWORD=hunter3",
			"KEYORIX_TARGET_KEK=base64kek",
			"KEYORIX_DYNAMIC_ADMIN_DSN=postgres://u:p@h/db",
		} {
			assert.NotContains(t, out, sensitive, "%s must not leak into the child environment", sensitive)
		}
	})

	t.Run("keeps ordinary and non-credential Keyorix vars intact", func(t *testing.T) {
		for _, keep := range []string{
			"PATH=/usr/bin",
			"HOME=/home/dev",
			"KEYORIX_PROJECT=payments",
			"KEYORIX_SERVER=https://x",
			"KEYORIX_ENV=production",
		} {
			assert.Contains(t, out, keep, "%s should still be passed to the child", keep)
		}
	})
}

func TestIsSensitiveKeyorixEnv(t *testing.T) {
	cases := map[string]bool{
		"KEYORIX_TOKEN":         true,
		"KEYORIX_API_KEY":       true,
		"KEYORIX_SIEM_TOKEN":    true,
		"KEYORIX_SMTP_PASSWORD": true,
		"KEYORIX_TARGET_KEK":    true,
		"KEYORIX_PROJECT":       false,
		"KEYORIX_SERVER":        false,
		"PATH":                  false,
		"SOME_OTHER_APP_TOKEN":  false, // not KEYORIX_-prefixed
	}
	for key, want := range cases {
		assert.Equal(t, want, isSensitiveKeyorixEnv(key), "key=%s", key)
	}
}
