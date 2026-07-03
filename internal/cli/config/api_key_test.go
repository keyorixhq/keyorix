package config

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
	t.Setenv("KEYORIX_API_KEY", "env-secret")

	if got := resolveAPIKey(cmd); got != "flag-secret" {
		t.Errorf("resolveAPIKey() = %q; want the --api-key flag value", got)
	}
}

func TestResolveAPIKey_FallsBackToEnvVar(t *testing.T) {
	cmd := newAPIKeyCmd()
	t.Setenv("KEYORIX_API_KEY", "env-secret")

	if got := resolveAPIKey(cmd); got != "env-secret" {
		t.Errorf("resolveAPIKey() = %q; want the KEYORIX_API_KEY env var value", got)
	}
}

func TestResolveAPIKey_EmptyWhenNeitherSet(t *testing.T) {
	cmd := newAPIKeyCmd()
	t.Setenv("KEYORIX_API_KEY", "")

	if got := resolveAPIKey(cmd); got != "" {
		t.Errorf("resolveAPIKey() = %q; want empty string (api-key stays optional for set-remote)", got)
	}
}
