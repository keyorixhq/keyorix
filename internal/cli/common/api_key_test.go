package common

import (
	"testing"

	"github.com/spf13/cobra"
)

func newAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("api-key", "", "")
	return cmd
}

func TestResolveAPIKey_FlagWins(t *testing.T) {
	cmd := newAPIKeyCmd()
	_ = cmd.Flags().Set("api-key", "flag-secret")
	t.Setenv(APIKeyEnvVar, "env-secret")

	got, err := ResolveAPIKey(cmd, false)
	if err != nil {
		t.Fatalf("ResolveAPIKey returned error: %v", err)
	}
	if got != "flag-secret" {
		t.Errorf("ResolveAPIKey() = %q; want the --api-key flag value", got)
	}
}

func TestResolveAPIKey_FallsBackToEnvVar(t *testing.T) {
	cmd := newAPIKeyCmd()
	t.Setenv(APIKeyEnvVar, "env-secret")

	got, err := ResolveAPIKey(cmd, false)
	if err != nil {
		t.Fatalf("ResolveAPIKey returned error: %v", err)
	}
	if got != "env-secret" {
		t.Errorf("ResolveAPIKey() = %q; want the KEYORIX_API_KEY env var value", got)
	}
}

func TestResolveAPIKey_EmptyWithoutPromptWhenNeitherSet(t *testing.T) {
	cmd := newAPIKeyCmd()
	t.Setenv(APIKeyEnvVar, "")

	got, err := ResolveAPIKey(cmd, false)
	if err != nil {
		t.Fatalf("ResolveAPIKey returned error: %v", err)
	}
	if got != "" {
		t.Errorf("ResolveAPIKey() = %q; want empty string when prompt=false and nothing is set", got)
	}
}
