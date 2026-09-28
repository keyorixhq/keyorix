//go:build noazure

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoAzureBuild_AzureAppRotationFailsBoot is B1's
// server-level fail-closed proof for rotation's azure-app backend.
func TestInitializeCoreService_NoAzureBuild_AzureAppRotationFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation = config.AutoRotationConfig{
		Backends: []config.RotationBackendConfig{
			{Name: "prod-azure-app", Type: "azure-app", AllowedRefs: []string{"prod/*"}},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a noazure build with an azure-app rotation backend configured")
	}
	for _, want := range []string{"prod-azure-app", "azure-app", "noazure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
