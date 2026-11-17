package delivery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestGoMailFindingSCRAMIterationsUnbounded pins finding TP1-GOMAIL-scram-iter
// (issue #4383) in wneessen/go-mail v0.8.2: smtp/auth_scram.go takes the
// iteration count of the SCRAM server-first message ("i=") from the relay and
// runs pbkdf2.Key with it, with no upper bound. The relay therefore chooses how much CPU the client spends
// before it can send its next line, and the client's I/O timeout does not
// interrupt it (it is CPU, not I/O). Keyorix reach: SMTPDelivery.newClient (and
// notifychan's EmailSink.newClient) configure SMTPAuthAutoDiscover whenever a
// relay username is set, which prefers SCRAM-SHA-256 whenever the relay lists it,
// with or without TLS; DeliverSetupLink runs in the admin's create-user request.
//
// The test drives that exact path (newClient, buildMessage,
// DialAndSendWithContext) against the in-memory relay with i=4096 and with
// i=1024000 and asserts the client accepted both, computing the proof (it sent a
// client-final message), and that the larger count cost much more time. When
// go-mail starts refusing large iteration counts it reports the finding closed
// (guardrules.KnownFindingClosed); then remove this test and
// scramIterKnownFinding in FuzzSetupLinkHostileSMTPServer, and close #4383.
//
// What this does NOT verify: the exact cost per iteration (machine-dependent);
// SCRAM-SHA-1, which shares the same code path.
func TestGoMailFindingSCRAMIterationsUnbounded(t *testing.T) {
	if testing.Short() {
		t.Skip("spends about a second of CPU on purpose")
	}
	prev := smtpRelayIdle
	// The relay hangs up when the client stays silent for this long, and the
	// client is silent while it computes PBKDF2; 60s takes the relay out of the
	// picture. The real bound is the client's own: go-mail's I/O deadline,
	// smtpDialTimeout (10s, set at connect, so PBKDF2 runs inside it), which the
	// test keeps because the client comes from SMTPDelivery.newClient. That is
	// why the big count is i=1024000 (250x the small one, the ratio check needs
	// 50x): about 0.15s plain and 1.5s under -race locally, where i=4096000 took
	// 6.5s under -race in the merge queue, too close to 10s.
	smtpRelayIdle = 60 * time.Second
	defer func() { smtpRelayIdle = prev }()
	run := func(iter string) (time.Duration, []string) {
		sc := &smtpScript{
			ehlo:      []string{"AUTH SCRAM-SHA-256"},
			authStep:  []string{"334 ", "334 {scram}", "535 no"},
			scramIter: iter,
		}
		rec := &smtpRecord{}
		cfg := SMTPSettings{Host: "relay.test", Port: 2525, From: fuzzFrom, TLS: smtpTLSNone, Username: fuzzSMTPUser, Password: fuzzSMTPPass}
		req := SetupLinkRequest{RecipientEmail: "alice@example.com", Link: "https://k/s"}
		start := time.Now()
		_, _ = sendViaPipe(t, cfg, req, sc, rec)
		return time.Since(start), rec.lines
	}
	small, smallLines := run("4096")
	big, bigLines := run("1024000")
	sentFinal := func(lines []string) bool {
		// AUTH, the client-first message, then the client-final message
		// (base64 of "c=biws,r=...,p=..."), which needs the derived key.
		return len(lines) >= 4 && strings.HasPrefix(lines[1], "AUTH SCRAM-SHA-256") && lines[3] != "*"
	}
	if !sentFinal(smallLines) {
		t.Fatalf("harness: the SCRAM dialogue did not reach the client-final message: %q", smallLines)
	}
	if !sentFinal(bigLines) {
		guardrules.KnownFindingClosed(t, "TP1-GOMAIL-scram-iter", fmt.Sprintf("no client-final for i=1024000 after %v (lines %q): either go-mail now refuses large counts (#4383 fixed) or a timeout (relay idle %v, client smtpDialTimeout %v) expired during PBKDF2; an elapsed time near either bound means a timeout", big, bigLines, smtpRelayIdle, smtpDialTimeout))
		return
	}
	if big < 50*small {
		t.Fatalf("i=1024000 took %v, i=4096 took %v: the iteration count no longer drives the cost", big, small)
	}
	t.Logf("i=4096: %v, i=1024000: %v", small, big)
}
