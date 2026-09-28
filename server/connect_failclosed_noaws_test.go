//go:build noaws

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestInitializeCoreService_NoAWSBuild_AWSConnectorFailsBoot is B1 (ADR-109
// step 6, S2)'s server-level fail-closed proof: a noaws build refuses to
// start when config.Connect names an aws-secrets-manager connector — the
// implementation was excluded at compile time (wireConnect returns an error,
// DefaultIntegrations propagates it, initializeCoreService wraps it) rather
// than the server silently booting without that connector or crashing later
// on first use.
func TestInitializeCoreService_NoAWSBuild_AWSConnectorFailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-aws", Type: "aws-secrets-manager", Scope: "platform"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot in a noaws build with an aws-secrets-manager connector configured")
	}
	for _, want := range []string{"prod-aws", "aws-secrets-manager", "noaws"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected boot error to name %q, got: %v", want, err)
		}
	}
}
