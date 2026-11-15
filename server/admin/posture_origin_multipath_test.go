package admin

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// originOfInsecureSetting runs the posture's insecure-settings pass and returns
// the origin label of the one deviation whose detail names name.
func originOfInsecureSetting(t *testing.T, cfg *config.Config, explicit map[string]bool, name string) deviationOrigin {
	t.Helper()
	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, explicit, report)
	for _, d := range report.deviations {
		if d.category == "insecure-setting" && strings.HasPrefix(d.detail, name+" is in effect") {
			return d.origin
		}
	}
	t.Fatalf("%s must be a counted deviation; got %+v", name, report.deviations)
	return ""
}

// Some registry entries read one key per listener or channel. The weak state
// can then come from the key the file did NOT write: a file that turns rate
// limiting on for HTTP only leaves gRPC unlimited by the shipped default, and
// the posture report must not call that explicit. Origin is decided by the
// keys behind the side that is weak, not by any key of the entry.
func TestPostureOrigin_PerListenerEntriesBlameTheWeakSideOnly(t *testing.T) {
	const (
		ratelimit = "server.insecure_disable_api_ratelimit"
		metrics   = "server.insecure_allow_unauthenticated_metrics"
		smtp      = "credential_delivery.insecure_allow_plaintext_smtp"
		shamir    = "storage.encryption.key_provider.insecure_omit_shamir_commitment_check"
	)
	cases := []struct {
		name     string
		setting  string
		cfg      func() *config.Config
		explicit []string
		want     deviationOrigin
	}{
		{"ratelimit: http on, grpc silent, file writes http only", ratelimit,
			func() *config.Config {
				c := &config.Config{}
				c.Server.HTTP.RateLimit.Enabled = true
				return c
			}, []string{"server.http.ratelimit.enabled"}, originShippedDefault},
		{"ratelimit: http on, grpc explicitly off", ratelimit,
			func() *config.Config {
				c := &config.Config{}
				c.Server.HTTP.RateLimit.Enabled = true
				return c
			}, []string{"server.http.ratelimit.enabled", "server.grpc.ratelimit.enabled"}, originExplicit},
		{"metrics: http token set, grpc silent, file writes http only", metrics,
			func() *config.Config {
				c := &config.Config{}
				c.Server.HTTP.MetricsToken = "t"
				return c
			}, []string{"server.http.metrics_token"}, originShippedDefault},
		{"metrics: http token set, grpc token explicitly empty", metrics,
			func() *config.Config {
				c := &config.Config{}
				c.Server.HTTP.MetricsToken = "t"
				return c
			}, []string{"server.http.metrics_token", "server.grpc.metrics_token"}, originExplicit},
		{"smtp: setup mail none by default, file writes notifications only", smtp,
			func() *config.Config {
				c := &config.Config{}
				c.CredentialDelivery.SMTP.TLS = "none"
				c.Notifications.Email.TLS = "starttls"
				return c
			}, []string{"notifications.email.tls"}, originShippedDefault},
		{"smtp: setup mail none written", smtp,
			func() *config.Config {
				c := &config.Config{}
				c.CredentialDelivery.SMTP.TLS = "none"
				c.Notifications.Email.TLS = "starttls"
				return c
			}, []string{"credential_delivery.smtp.tls", "notifications.email.tls"}, originExplicit},
		{"shamir: primary pinned, fallback silent", shamir,
			func() *config.Config {
				c := &config.Config{}
				c.Storage.Encryption.Enabled = true
				c.Storage.Encryption.KeyProvider = config.KeyProviderConfig{Type: "shamir", ShamirCommitment: "ab"}
				c.Storage.Encryption.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir"}}
				return c
			}, []string{"storage.encryption.key_provider.shamir_commitment"}, originShippedDefault},
		{"shamir: fallback commitment written empty", shamir,
			func() *config.Config {
				c := &config.Config{}
				c.Storage.Encryption.Enabled = true
				c.Storage.Encryption.KeyProvider = config.KeyProviderConfig{Type: "shamir", ShamirCommitment: "ab"}
				c.Storage.Encryption.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir"}}
				return c
			}, []string{"storage.encryption.key_provider.shamir_commitment", "storage.encryption.key_provider.fallbacks.shamir_commitment"}, originExplicit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			explicit := map[string]bool{}
			for _, p := range tc.explicit {
				explicit[p] = true
			}
			got := originOfInsecureSetting(t, tc.cfg(), explicit, tc.setting)
			assert.Equal(t, tc.want, got)
		})
	}
	require.NotEmpty(t, cases)
}

// The narrowing tables must cover every registry entry that reads more than one
// key, so a new per-listener entry cannot silently fall back to "any path counts".
func TestPostureOrigin_MultiPathEntriesAreNarrowedOrExempt(t *testing.T) {
	multi := map[string]bool{}
	for _, s := range config.InsecureSettingsRegistry {
		if len(s.SourcePaths) < 2 {
			continue
		}
		multi[s.Name] = true
		_, narrowed := perSideSourcePaths[s.Name]
		reason, exempt := multiPathUnnarrowed[s.Name]
		assert.True(t, narrowed || exempt, "%s reads %v: narrow it in perSideSourcePaths or exempt it in multiPathUnnarrowed with a reason", s.Name, s.SourcePaths)
		assert.False(t, narrowed && exempt, "%s is both narrowed and exempt", s.Name)
		if exempt {
			assert.NotEmpty(t, reason, "%s: an exemption needs a reason", s.Name)
		}
	}
	// The Shamir entry has one source path but is narrowed per chain member, so
	// a narrowing row only has to name a real registry entry.
	registered := map[string]bool{}
	for _, s := range config.InsecureSettingsRegistry {
		registered[s.Name] = true
	}
	for name := range perSideSourcePaths {
		assert.True(t, registered[name], "perSideSourcePaths names %q, which is not a registry entry", name)
	}
	for name := range multiPathUnnarrowed {
		assert.True(t, multi[name], "multiPathUnnarrowed names %q, which is not a multi-path registry entry", name)
	}
}
