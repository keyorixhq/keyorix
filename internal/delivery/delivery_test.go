package delivery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("empty mode defaults to auto → out-of-band when no SMTP", func(t *testing.T) {
		d, err := New(Config{})
		require.NoError(t, err)
		assert.Equal(t, ChannelOutOfBand, d.Name())
	})

	t.Run("out_of_band selects OutOfBandDelivery", func(t *testing.T) {
		d, err := New(Config{Mode: ModeOutOfBand})
		require.NoError(t, err)
		assert.IsType(t, &OutOfBandDelivery{}, d)
	})

	t.Run("log refuses to activate without the explicit opt-in env var", func(t *testing.T) {
		t.Setenv(EnvAllowInsecureLogDelivery, "")
		_, err := New(Config{Mode: ModeLog})
		require.Error(t, err, "mode=log discloses a live setup link into the log; it must fail closed by default")
	})

	t.Run("log selects LogDelivery once the operator opts in", func(t *testing.T) {
		t.Setenv(EnvAllowInsecureLogDelivery, "true")
		d, err := New(Config{Mode: ModeLog})
		require.NoError(t, err)
		assert.IsType(t, &LogDelivery{}, d)
	})

	t.Run("smtp with a configured relay selects SMTPDelivery", func(t *testing.T) {
		d, err := New(Config{Mode: ModeSMTP, SMTP: SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io"}})
		require.NoError(t, err)
		assert.IsType(t, &SMTPDelivery{}, d)
		assert.Equal(t, ChannelSMTP, d.Name())
	})

	t.Run("smtp without a host errors at construction", func(t *testing.T) {
		_, err := New(Config{Mode: ModeSMTP})
		require.Error(t, err)
	})

	t.Run("auto with SMTP configured selects SMTPDelivery", func(t *testing.T) {
		d, err := New(Config{Mode: ModeAuto, SMTP: SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io"}})
		require.NoError(t, err)
		assert.IsType(t, &SMTPDelivery{}, d)
	})

	t.Run("unknown mode errors", func(t *testing.T) {
		_, err := New(Config{Mode: "carrier-pigeon"})
		require.Error(t, err)
	})
}

func TestOutOfBandDelivery(t *testing.T) {
	d := &OutOfBandDelivery{}
	ctx := context.Background()

	t.Run("returns the link for the admin to relay, sends nothing", func(t *testing.T) {
		res, err := d.DeliverSetupLink(ctx, SetupLinkRequest{
			RecipientEmail: "new@acme.io",
			Link:           "https://keyorix.acme.internal/auth/setup/kx_setup_abc",
		})
		require.NoError(t, err)
		assert.Equal(t, ChannelOutOfBand, res.Channel)
		assert.False(t, res.Delivered)
		assert.Equal(t, "https://keyorix.acme.internal/auth/setup/kx_setup_abc", res.LinkForAdmin)
	})

	t.Run("errors on an empty link", func(t *testing.T) {
		_, err := d.DeliverSetupLink(ctx, SetupLinkRequest{RecipientEmail: "new@acme.io"})
		require.Error(t, err)
	})
}

func TestLogDelivery(t *testing.T) {
	d := &LogDelivery{}
	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{
		RecipientEmail: "new@acme.io",
		Link:           "https://keyorix.acme.internal/auth/setup/kx_setup_abc",
	})
	require.NoError(t, err)
	assert.Equal(t, ChannelLog, res.Channel)
	assert.True(t, res.Delivered)
}
