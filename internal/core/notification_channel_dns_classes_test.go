package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3427 (b): TestNotificationChannel_CreateAndUpdateRefuseResolvedPrivateHost
// pins 10.0.0.5 and a resolve failure. A hostname can also resolve to loopback,
// cloud IMDS, other RFC1918 ranges, IPv6 loopback/link-local/ULA, or an IPv4
// address wrapped in an IPv6 form. Each is refused at CREATE through the real
// validator (no webhookURLValidator override, injected resolver, no real DNS).
func TestCreateNotificationChannel_RefusesEveryDisallowedResolvedClass(t *testing.T) {
	const host = "https://hooks.internal.test/services/T/B/TOKEN"
	for name, answer := range map[string]string{
		"loopback v4":        "127.0.0.1",
		"imds link-local":    "169.254.169.254",
		"rfc1918 192.168":    "192.168.1.10",
		"rfc1918 172.16":     "172.16.0.9",
		"rfc1918 10 top":     "10.255.255.255",
		"unspecified v4":     "0.0.0.0",
		"loopback v6":        "::1",
		"link-local v6":      "fe80::1",
		"unique-local v6":    "fc00::1",
		"v4-mapped private":  "::ffff:10.0.0.5",
		"v4-mapped loopback": "::ffff:127.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			resolverFor(t, []string{answer}, nil)
			c := NewKeyorixCore(new(MockStorage)) // no expectations: any write panics
			created, err := c.CreateNotificationChannel(context.Background(),
				&models.NotificationChannel{Name: "n", Type: "webhook", URL: host, Enabled: true}, "tester", 1)
			require.Error(t, err, "%s must be refused", answer)
			assert.Nil(t, created)
			assert.Contains(t, err.Error(), "private/link-local")
		})
	}
}

// TestCreateNotificationChannel_DNSGuardHarnessDetectsWeakenedGuard shows the
// refusal assertions above can go red. The weakened guard is test-local: a
// stand-in validator (injected through the webhookURLValidator seam) that
// resolves like validateWebhookURL but never checks the answer. With it, the
// very same private resolution that must be refused is accepted. No production
// file is edited.
func TestCreateNotificationChannel_DNSGuardHarnessDetectsWeakenedGuard(t *testing.T) {
	const host = "https://hooks.internal.test/services/T/B/TOKEN"
	resolverFor(t, []string{"10.0.0.5"}, nil)

	// Real guard: refused.
	require.Error(t, validateWebhookURL(host))

	// Weakened copy: resolves, then waves every answer through.
	weakened := func(raw string) error {
		u, err := parseWebhookURLLiteral(raw)
		if err != nil {
			return err
		}
		_, err = channelLookupIPAddr(context.Background(), u.Hostname())
		return err
	}
	assert.NoError(t, weakened(host), "weakened guard accepts the private resolution: the refusal tests would go red against it")

	// Driven through CreateNotificationChannel, the weakened validator lets the
	// same private resolution reach storage: the create succeeds and the mock's
	// CreateNotificationChannel expectation is met. The refusal tests above go
	// through the real validator, so they would fail against this one. (Swap
	// `weakened` for validateWebhookURL here and this test goes red: create
	// returns "private/link-local" and the storage write never happens.)
	store := new(MockStorage)
	store.On("CreateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("UpdateNotificationChannel", mock.Anything, mock.Anything).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()
	c := NewKeyorixCore(store)
	c.webhookURLValidator = weakened
	created, err := c.CreateNotificationChannel(context.Background(),
		&models.NotificationChannel{Name: "n", Type: "webhook", URL: host, Enabled: true}, "tester", 1)
	require.NoError(t, err, "weakened validator must let the private resolution through create")
	require.NotNil(t, created)
	store.AssertCalled(t, "CreateNotificationChannel", mock.Anything, mock.Anything)
}
