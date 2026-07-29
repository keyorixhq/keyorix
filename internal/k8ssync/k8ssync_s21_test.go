package k8ssync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetHealthPort_S21 covers the GetHealthPort getter: returns the configured
// port when set, and the default 8080 when unset or zero.
func TestGetHealthPort_S21(t *testing.T) {
	cases := []struct {
		name     string
		port     int
		wantPort int
	}{
		{"explicit port", 9090, 9090},
		{"another port", 3000, 3000},
		{"zero uses default", 0, 8080},
		{"negative uses default", -1, 8080},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{HealthPort: c.port}
			assert.Equal(t, c.wantPort, cfg.GetHealthPort())
		})
	}
}

// TestGetInterval_S21 covers the GetInterval getter: returns the configured
// duration when valid and positive, and the default 5m otherwise.
func TestGetInterval_S21(t *testing.T) {
	cases := []struct {
		name         string
		interval     string
		wantDuration time.Duration
	}{
		{"explicit 10m", "10m", 10 * time.Minute},
		{"explicit 1h", "1h", time.Hour},
		{"explicit 30s", "30s", 30 * time.Second},
		{"empty uses default", "", 5 * time.Minute},
		{"invalid uses default", "not-a-duration", 5 * time.Minute},
		{"zero duration uses default", "0s", 5 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{Interval: c.interval}
			assert.Equal(t, c.wantDuration, cfg.GetInterval())
		})
	}
}

// TestRequireHTTPSURL_S21 covers requireHTTPSURL directly for all branches:
// https (allowed), http+localhost (allowed), http+loopback IP (rejected — K8SSYNC-007),
// http+non-loopback (rejected), invalid URL (rejected), non-http/https (rejected).
func TestRequireHTTPSURL_S21(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https allowed", "https://keyorix.example.com", false},
		{"https with port allowed", "https://keyorix.example.com:8443", false},
		{"http localhost allowed", "http://localhost:8080", false},
		{"http 127.0.0.1 rejected", "http://127.0.0.1:8080", true},
		{"http ::1 rejected", "http://[::1]:8080", true},
		{"http non-loopback rejected", "http://10.0.0.1:8080", true},
		{"http public host rejected", "http://keyorix.example.com", true},
		{"ftp scheme rejected", "ftp://keyorix.example.com", true},
		{"no host rejected", "not-a-url", true},
		{"empty string rejected", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := requireHTTPSURL(c.url)
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestLoadConfig_S21 covers LoadConfig: missing file, invalid YAML, validation
// errors, and a fully valid config.
func TestLoadConfig_S21(t *testing.T) {
	t.Run("missing file returns error", func(t *testing.T) {
		_, err := LoadConfig("/does/not/exist/config.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read config")
	})

	t.Run("invalid YAML returns error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "bad.yaml")
		require.NoError(t, os.WriteFile(f, []byte(":\tinvalid: yaml: ["), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse config")
	})

	t.Run("missing keyorix_url returns error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "mappings:\n  - ref: prod/db\n    namespace: default\n    name: creds\n    key: DB\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyorix_url is required")
	})

	t.Run("no mappings returns error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "keyorix_url: https://keyorix.example.com\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one mapping is required")
	})

	t.Run("invalid interval returns error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "keyorix_url: https://keyorix.example.com\ninterval: badval\nmappings:\n  - ref: prod/db\n    namespace: default\n    name: creds\n    key: DB\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid interval")
	})

	t.Run("invalid mapping returns error", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "keyorix_url: https://keyorix.example.com\nmappings:\n  - ref: \"\"\n    namespace: default\n    name: creds\n    key: DB\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mapping 0")
	})

	t.Run("valid config loads successfully", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "keyorix_url: https://keyorix.example.com\ninterval: 10m\nhealth_port: 9090\ncleanup: true\nmappings:\n  - ref: prod/db\n    namespace: default\n    name: creds\n    key: DB\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		cfg, err := LoadConfig(f)
		require.NoError(t, err)
		assert.Equal(t, "https://keyorix.example.com", cfg.KeyorixURL)
		assert.Equal(t, 10*time.Minute, cfg.GetInterval())
		assert.Equal(t, 9090, cfg.GetHealthPort())
		assert.True(t, cfg.Cleanup)
		assert.Len(t, cfg.Mappings, 1)
	})

	t.Run("http non-loopback url rejected", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "cfg.yaml")
		yaml := "keyorix_url: http://keyorix.example.com\nmappings:\n  - ref: prod/db\n    namespace: default\n    name: creds\n    key: DB\n"
		require.NoError(t, os.WriteFile(f, []byte(yaml), 0600))
		_, err := LoadConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must use https")
	})
}
