//go:build noazure

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoAzureBuild_AzureConnectorFailsBoot is B1's
// server-level fail-closed proof for connect's azure-key-vault backend.
func TestInitializeCoreService_NoAzureBuild_AzureConnectorFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-azure", Type: "azure-key-vault", Scope: "platform", Address: "https://example.vault.azure.net"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a noazure build with an azure-key-vault connector configured")
	}
	for _, want := range []string{"prod-azure", "azure-key-vault", "noazure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
