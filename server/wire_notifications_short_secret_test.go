package main

import (
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// TestWireNotificationChannels_ShortSigningSecretWarning drives the boot wiring
// step: a short signing secret leaves the webhook channel wired and logs a
// warning naming its length and never its value; a full-length one logs none.
// Under the real GODEBUG=fips140=only there is no warning, because config
// validation has already refused such a secret before this step runs.
func TestWireNotificationChannels_ShortSigningSecretWarning(t *testing.T) {
	t.Setenv("KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET", "")
	run := func(secret string) string {
		cfg := &config.Config{}
		cfg.Notifications.Webhook = config.NotificationWebhookConfig{
			Enabled: true, Endpoint: "https://127.0.0.1:1/hook", AllowPrivateNetworkTarget: true, SigningSecret: secret,
		}
		var err error
		out := captureLogs(func() { err = wireNotificationChannels(&coreWiring{cfg: cfg, core: core.NewKeyorixCore(nil)}) })
		require.NoError(t, err)
		require.Contains(t, out, "Notification webhook channel enabled")
		return out
	}

	out := run("13-byte-value")
	if fips140.Enforced() {
		require.NotContains(t, out, "signing_secret")
	} else {
		require.Contains(t, out, "WARNING: notifications.webhook.signing_secret (or KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET) is 13 bytes")
	}
	require.NotContains(t, out, "13-byte-value", "the log must never contain the secret")

	require.NotContains(t, run("a-full-length-signing-secret"), "signing_secret")
}
