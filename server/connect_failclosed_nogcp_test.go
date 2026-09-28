//go:build nogcp

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoGCPBuild_GCPConnectorFailsBoot is B1's
// server-level fail-closed proof for connect's gcp-secret-manager backend.
func TestInitializeCoreService_NoGCPBuild_GCPConnectorFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-gcp", Type: "gcp-secret-manager", Scope: "platform", ProjectID: "my-project"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a nogcp build with a gcp-secret-manager connector configured")
	}
	for _, want := range []string{"prod-gcp", "gcp-secret-manager", "nogcp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
