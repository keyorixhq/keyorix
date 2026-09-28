//go:build noaws

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoAWSBuild_AWSIAMRotationFailsBoot is B1 (ADR-109
// step 6, S2)'s server-level fail-closed proof for rotation's aws-iam
// backend: a noaws build refuses to start when config.AutoRotation names an
// aws-iam backend (wireBackendRotation returns an error, DefaultIntegrations
// propagates it, initializeCoreService wraps it).
func TestInitializeCoreService_NoAWSBuild_AWSIAMRotationFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation = config.AutoRotationConfig{
		Backends: []config.RotationBackendConfig{
			{Name: "prod-aws-iam", Type: "aws-iam", AllowedRefs: []string{"prod/*"}},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a noaws build with an aws-iam rotation backend configured")
	}
	for _, want := range []string{"prod-aws-iam", "aws-iam", "noaws"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
