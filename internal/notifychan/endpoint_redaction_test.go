package notifychan

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

// #3805: a Slack/Teams incoming-webhook URL is itself the bearer credential, and
// validateEndpoint's errors are returned by NewChat/NewWebhook as startup
// failures that end in the log. None of them may carry the URL's path.
const (
	leakPath  = "/services/T0AAAAAAA/B0BBBBBBB/xoxb-secret-token-ZZZ"
	leakToken = "xoxb-secret-token-ZZZ"
)

func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	for _, bad := range []string{leakToken, leakPath, "T0AAAAAAA"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error text leaks %q: %v", bad, err)
		}
	}
	// RedactErrorURLs removes every *url.Error layer (the one that holds the full
	// URL) from the chain; errors.As must not be able to recover it.
	if ue, ok := errors.AsType[*url.Error](err); ok {
		t.Errorf("a *url.Error is still reachable through the chain: %v", ue)
	}
}

func TestValidateEndpoint_ErrorsNeverCarryTheURLPath(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()

	t.Run("resolve fails, resolver error quotes the URL", func(t *testing.T) {
		raw := "https://hooks.slack.com" + leakPath
		lookupIPAddr = func(host string) ([]net.IPAddr, error) {
			return nil, errors.New(`lookup ` + host + ` for "` + raw + `": no such host`)
		}
		err := validateEndpoint(raw, false, false)
		assertNoLeak(t, err)
		if !strings.Contains(err.Error(), "hooks.slack.com") {
			t.Errorf("error should still name the host: %v", err)
		}
	})
	t.Run("resolves to a private address", func(t *testing.T) {
		lookupIPAddr = func(string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.7")}}, nil
		}
		assertNoLeak(t, validateEndpoint("https://hooks.slack.com"+leakPath, false, false))
	})
	t.Run("literal private address", func(t *testing.T) {
		assertNoLeak(t, validateEndpoint("https://169.254.169.254"+leakPath, false, false))
	})
	t.Run("plaintext http to a public host", func(t *testing.T) {
		assertNoLeak(t, validateEndpoint("http://hooks.slack.com"+leakPath, false, false))
	})
	t.Run("wrong scheme", func(t *testing.T) {
		assertNoLeak(t, validateEndpoint("ftp://hooks.slack.com"+leakPath, false, false))
	})
	t.Run("unparseable URL", func(t *testing.T) {
		assertNoLeak(t, validateEndpoint("https://hooks.slack.com"+leakPath+"\x7f", false, false))
	})
}

// The same failures through the constructors that surface them at startup.
func TestNewChatAndWebhook_StartupErrorsNeverCarryTheURLPath(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	raw := "https://hooks.slack.com" + leakPath
	lookupIPAddr = func(string) ([]net.IPAddr, error) {
		return nil, errors.New(`lookup failed for "` + raw + `"`)
	}
	_, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: raw})
	assertNoLeak(t, err)
	_, err = NewWebhook(WebhookConfig{Endpoint: raw})
	assertNoLeak(t, err)
}
