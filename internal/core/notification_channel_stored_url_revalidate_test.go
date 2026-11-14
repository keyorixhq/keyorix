// notification_channel_stored_url_revalidate_test.go -- #3625 (CodeQL #1209).
//
// The create/update-time URL check cannot vouch for a row rewritten afterwards.
// decryptNotificationChannelURL re-runs the validator on the decrypted value
// before any caller can use it. The ciphertext below is a perfectly valid,
// AAD-bound envelope for the channel's own id: only the URL inside it is bad,
// which is what a tampered at-rest row (or a pre-guard row) looks like.
package core

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const storedURLToken = "STOREDURLTOKEN"

func TestDecryptNotificationChannelURL_PrivateIPCiphertextRefused(t *testing.T) {
	t.Parallel()
	for name, bad := range map[string]string{
		"imds link-local": "https://169.254.169.254/latest/meta-data/" + storedURLToken,
		"loopback":        "https://127.0.0.1/hook/" + storedURLToken,
		"rfc1918":         "https://10.0.0.5/services/T/B/" + storedURLToken,
		"plain http":      "http://hooks.example.com/services/T/B/" + storedURLToken,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, db, _, id := newEncryptedChannelWorld(t)
			ctx := context.Background()
			c.webhookURLValidator = nil // production validator, not the test no-op

			urlEnc, urlMeta, err := c.encryptNotificationChannelURL(bad, id)
			require.NoError(t, err)
			setURLEnc(t, db, id, urlEnc, urlMeta)

			got, err := c.GetNotificationChannel(ctx, id)
			require.Error(t, err, "a ciphertext that decrypts to a refused destination must not be returned for use")
			assert.Nil(t, got)
			assert.NotContains(t, errString(err), storedURLToken, "the refusal must not echo the stored URL (#3426)")

			_, lerr := c.ListNotificationChannels(ctx)
			require.Error(t, lerr, "the fail-closed list must refuse the row too")

			// Send time: the alert path reads the channel through the core wrapper, so
			// the escalation is not sent and the transport is never reached.
			c.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("a refused stored URL must never reach the transport")
				return nil, nil
			})}
			sent := c.dispatchPolicyChannels(ctx, &models.AnomalyAlert{ID: 1},
				&models.AlertEscalationPolicy{ID: 1, ChannelIDs: strconv.FormatUint(uint64(id), 10)})
			assert.False(t, sent, "escalation must not be delivered to a refused stored destination")
		})
	}
}

// Green control: the same tampering path with a public https URL still decrypts,
// so the red cases above are about the destination and not about the fixture.
func TestDecryptNotificationChannelURL_PublicCiphertextAccepted(t *testing.T) {
	t.Parallel()
	c, db, _, id := newEncryptedChannelWorld(t)
	c.webhookURLValidator = nil

	const good = "https://hooks.slack.test/services/T000/B000/" + storedURLToken
	urlEnc, urlMeta, err := c.encryptNotificationChannelURL(good, id)
	require.NoError(t, err)
	setURLEnc(t, db, id, urlEnc, urlMeta)

	got, err := c.GetNotificationChannel(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, good, got.URL)
}
