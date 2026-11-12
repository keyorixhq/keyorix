package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3427 (a), escalation half: TestPostJSONToURL_RefusesRedirectToSecondHost
// pins noEscalationRedirect on postJSONToURL directly. These tests drive the
// same guard through the real alert-ESCALATION entry point (RunAlertEscalation
// -> dispatchPolicyChannels -> dispatchToChannel -> postJSONToURL), so a future
// refactor that gives escalation its own client cannot silently drop the
// refusal.

// escalationRedirectRun is what a RunAlertEscalation against a redirecting
// receiver left behind.
type escalationRedirectRun struct {
	result      *EscalationResult
	logs        string
	firstHits   int32
	followedHit int32    // POSTs the redirect target actually received
	dialed      []string // every destination the transport was asked to dial
}

// runEscalationAgainstRedirect points one webhook channel at a local TLS
// receiver that answers every POST with a 302 to redirectTarget. Only the
// transport's dial target is swapped (so the two hostnames used here reach two
// local servers); the client under test is c.httpClient when set, else the
// production one built by postJSONToURL (CheckRedirect: noEscalationRedirect).
func runEscalationAgainstRedirect(t *testing.T, redirectTarget string, client func(*http.Transport) *http.Client) escalationRedirectRun {
	t.Helper()
	const firstHost = "hooks.first.test"

	var run escalationRedirectRun
	var followed atomic.Int32
	var first atomic.Int32
	landing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer landing.Close()
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		http.Redirect(w, r, redirectTarget, http.StatusFound)
	}))
	defer receiver.Close()

	pool := x509.NewCertPool()
	pool.AddCert(receiver.Certificate())

	var mu sync.Mutex
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			run.dialed = append(run.dialed, addr)
			mu.Unlock()
			switch addr {
			case net.JoinHostPort(firstHost, "443"):
				return (&net.Dialer{}).DialContext(ctx, network, receiver.Listener.Addr().String())
			case net.JoinHostPort("hooks.second.test", "443"):
				return (&net.Dialer{}).DialContext(ctx, network, landing.Listener.Addr().String())
			}
			// Loopback / private / link-local redirect targets: record the
			// attempt, but never connect anywhere.
			return nil, errors.New("test dialer: refusing to connect to " + addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
	}
	orig := escalationTransport
	defer func() { escalationTransport = orig }()
	escalationTransport = transport

	store := new(MockStorage)
	now := time.Now().UTC()
	p := makePolicy(1, "p1", "medium", 30)
	p.ChannelIDs = "7"
	alert := makeAlert(1, "high", 60)
	alert.DetectedAt = now.Add(-60 * time.Minute)
	ch := &models.NotificationChannel{ID: 7, Name: "redirecting", Type: "webhook", URLEnc: plaintextURLEnc("https://" + firstHost + "/hook"), Enabled: true}
	store.On("ListAlertEscalationPolicies", mock.Anything).Return([]models.AlertEscalationPolicy{p}, nil)
	store.On("ListUnacknowledgedAnomalyAlertsBefore", mock.Anything, mock.Anything).Return([]models.AnomalyAlert{alert}, nil)
	store.On("GetNotificationChannel", mock.Anything, uint(7)).Return(ch, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	c := NewKeyorixCore(store)
	c.now = fixedNow(now)
	if client != nil {
		c.httpClient = client(transport)
	}

	var buf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOut)

	res, err := c.RunAlertEscalation(context.Background())
	require.NoError(t, err)
	run.result = res
	run.logs = buf.String()
	run.firstHits = first.Load()
	run.followedHit = followed.Load()
	return run
}

// Redirect targets an attacker-controlled receiver would pick: a second public
// host, loopback, RFC1918, cloud IMDS and an IPv6 loopback literal.
var escalationRedirectTargets = map[string]string{
	"second public host": "https://hooks.second.test/stolen",
	"loopback":           "https://127.0.0.1:8443/admin",
	"private":            "https://10.0.0.5/internal",
	"link-local IMDS":    "https://169.254.169.254/latest/meta-data/",
	"ipv6 loopback":      "https://[::1]:8443/admin",
}

// TestRunAlertEscalation_RefusesRedirect: the escalation POST goes out once, the
// 3xx is refused, the redirect target is never dialed, and the alert is counted
// as skipped (not escalated). Remove `CheckRedirect: noEscalationRedirect` from
// postJSONToURL and every subtest goes red (see the weakened-guard test below,
// which proves this harness detects that).
func TestRunAlertEscalation_RefusesRedirect(t *testing.T) {
	for name, target := range escalationRedirectTargets {
		t.Run(name, func(t *testing.T) {
			run := runEscalationAgainstRedirect(t, target, nil) // nil: production client

			assert.EqualValues(t, 1, run.firstHits, "the configured receiver is contacted exactly once")
			assert.Equal(t, 0, run.result.Escalated, "a redirected delivery is not a delivery")
			assert.Equal(t, 1, run.result.Skipped)
			assert.Contains(t, run.logs, "redirect refused", "the failure must come from noEscalationRedirect")
			assert.EqualValues(t, 0, run.followedHit, "the redirect target must receive nothing")
			assert.Equal(t, []string{"hooks.first.test:443"}, run.dialed,
				"nothing but the configured host may be dialed; the redirect target must not be")
		})
	}
}

// TestRunAlertEscalation_RedirectHarnessDetectsWeakenedGuard shows the test
// above can go red: the same harness, but with a test-local WEAKENED copy of the
// production client that follows redirects (net/http default CheckRedirect). The
// redirect target is then dialed, and the second host receives the POST. No
// production file is edited.
func TestRunAlertEscalation_RedirectHarnessDetectsWeakenedGuard(t *testing.T) {
	weakened := func(tr *http.Transport) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: tr} // CheckRedirect: nil == follow
	}

	// All five targets of the guarded test above. Each one must be dialed once the
	// guard is gone; the second public host also receives the re-sent POST.
	wantDial := map[string]string{
		"second public host": "hooks.second.test:443",
		"loopback":           "127.0.0.1:8443",
		"private":            "10.0.0.5:443",
		"link-local IMDS":    "169.254.169.254:443",
		"ipv6 loopback":      "[::1]:8443",
	}
	require.Len(t, wantDial, len(escalationRedirectTargets), "keep wantDial in step with escalationRedirectTargets")
	for name, target := range escalationRedirectTargets {
		t.Run(name+" is reached", func(t *testing.T) {
			addr, ok := wantDial[name]
			require.True(t, ok, "no expected dial address for %q", name)
			run := runEscalationAgainstRedirect(t, target, weakened)
			assert.Contains(t, run.dialed, addr, "weakened guard: the client followed the redirect and dialed the target")
			assert.NotContains(t, run.logs, "redirect refused")
			if name == "second public host" {
				assert.EqualValues(t, 1, run.followedHit, "weakened guard: the redirect was followed and the POST re-sent")
				assert.Equal(t, 1, run.result.Escalated)
			}
		})
	}
}
