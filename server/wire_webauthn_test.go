package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// TestWireWebAuthn drives the wiring step (ADR-036; CORE-DECOUPLE-WEBAUTHN-1
// moved the relying party to internal/webauthnrp): no webauthn block leaves
// passkeys disabled and logs nothing; a valid block enables them with the
// startup line operators grep for; a block the library refuses stops the boot
// with "failed to init WebAuthn" and leaves passkeys disabled.
func TestWireWebAuthn(t *testing.T) {
	run := func(wa config.WebAuthnConfig) (*core.KeyorixCore, string, error) {
		cfg := &config.Config{}
		cfg.WebAuthn = wa
		c := core.NewKeyorixCore(nil)
		var err error
		out := captureLogs(func() { err = wireWebAuthn(&coreWiring{cfg: cfg, core: c}) })
		return c, out, err
	}

	c, out, err := run(config.WebAuthnConfig{})
	require.NoError(t, err)
	require.False(t, c.WebAuthnEnabled())
	require.NotContains(t, out, "WebAuthn")

	c, out, err = run(config.WebAuthnConfig{Enabled: true, RPID: "keyorix.example", RPOrigins: []string{"https://keyorix.example"}})
	require.NoError(t, err)
	require.True(t, c.WebAuthnEnabled())
	require.Contains(t, out, `WebAuthn enabled (RP ID "keyorix.example", 1 origin(s))`)

	c, _, err = run(config.WebAuthnConfig{Enabled: true, RPID: "keyorix.example"})
	require.ErrorContains(t, err, "failed to init WebAuthn: ")
	require.False(t, c.WebAuthnEnabled(), "a refused config must not leave a relying party behind")
}
