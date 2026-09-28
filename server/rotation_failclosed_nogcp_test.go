//go:build nogcp

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoGCPBuild_GCPServiceAccountRotationFailsBoot is
// B1's server-level fail-closed proof for rotation's gcp-service-account
// backend.
func TestInitializeCoreService_NoGCPBuild_GCPServiceAccountRotationFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation = config.AutoRotationConfig{
		Backends: []config.RotationBackendConfig{
			{Name: "prod-gcp-sa", Type: "gcp-service-account", AllowedRefs: []string{"prod/*"}},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a nogcp build with a gcp-service-account rotation backend configured")
	}
	for _, want := range []string{"prod-gcp-sa", "gcp-service-account", "nogcp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
