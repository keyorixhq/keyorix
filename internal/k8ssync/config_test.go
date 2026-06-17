package k8ssync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k8s-sync.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func TestLoadConfig_Valid(t *testing.T) {
	p := writeConfig(t, `
keyorix_url: https://keyorix.internal
interval: 2m
mappings:
  - ref: production/db-password
    namespace: app
    name: db-creds
    key: DB_PASSWORD
  - ref: production/api-key
    namespace: app
    name: db-creds
    key: API_KEY
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	assert.Equal(t, "https://keyorix.internal", cfg.KeyorixURL)
	assert.Equal(t, 2*time.Minute, cfg.GetInterval())
	require.Len(t, cfg.Mappings, 2)
	assert.Equal(t, "production/db-password", cfg.Mappings[0].Ref)
	assert.Equal(t, "DB_PASSWORD", cfg.Mappings[0].Key)
}

func TestLoadConfig_DefaultInterval(t *testing.T) {
	p := writeConfig(t, `
keyorix_url: https://k
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`)
	cfg, err := LoadConfig(p)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, cfg.GetInterval(), "interval defaults to 5m when unset")
}

func TestLoadConfig_Invalid(t *testing.T) {
	cases := map[string]string{
		"missing url": `
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
		"no mappings": `
keyorix_url: https://k
`,
		"bad mapping": `
keyorix_url: https://k
mappings:
  - {ref: e/n, namespace: ns, name: s}
`,
		"bad interval": `
keyorix_url: https://k
interval: "soon"
mappings:
  - {ref: e/n, namespace: ns, name: s, key: K}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, body))
			assert.Error(t, err)
		})
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.Error(t, err)
}

func TestSync_LogsSummary(t *testing.T) {
	var lines []string
	logf := func(format string, args ...interface{}) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	f := &fakeFetcher{values: map[string][]byte{"e/n": []byte("v")}}
	s := newFakeSink()
	res := Sync(context.Background(), NewEngine(f, s), []SecretMapping{
		{Ref: "e/n", Namespace: "ns", Name: "sec", Key: "K"},
	}, logf)

	assert.Equal(t, 1, res.Created)
	require.NotEmpty(t, lines)
	assert.Contains(t, lines[0], "created=1")
	assert.Contains(t, lines[0], "failed=0")
}
