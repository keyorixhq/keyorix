package delivery

import (
	"strings"
	"testing"
	"time"
)

// TestGoMailFindingSCRAMIterationsUnbounded pins finding TP1-GOMAIL-scram-iter in
// wneessen/go-mail v0.8.1: smtp/auth_scram.go takes the iteration count of the
// SCRAM server-first message ("i=") from the relay and runs pbkdf2.Key with it,
// with no upper bound. The relay therefore chooses how much CPU the client spends
// before it can send its next line, and the client's I/O timeout does not
// interrupt it (it is CPU, not I/O). Keyorix reach: SMTPDelivery.newClient (and
// notifychan's EmailSink.newClient) configure SMTPAuthAutoDiscover whenever a
// relay username is set, which prefers SCRAM-SHA-256 whenever the relay lists it,
// with or without TLS; DeliverSetupLink runs in the admin's create-user request.
//
// The test drives that exact path (newClient, buildMessage,
// DialAndSendWithContext) against the in-memory relay with i=4096 and with
// i=4096000 and asserts the client accepted both, computing the proof (it sent a
// client-final message), and that the larger count cost much more time. It goes
// red when go-mail starts refusing large iteration counts; then remove this test
// and the large-iteration exclusion in FuzzSetupLinkHostileSMTPServer (if any).
//
// What this does NOT verify: the exact cost per iteration (machine-dependent);
// SCRAM-SHA-1, which shares the same code path.
func TestGoMailFindingSCRAMIterationsUnbounded(t *testing.T) {
	if testing.Short() {
		t.Skip("spends about a second of CPU on purpose")
	}
	prev := smtpRelayIdle
	smtpRelayIdle = 3 * time.Second
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
	big, bigLines := run("4096000")
	sentFinal := func(lines []string) bool {
		// AUTH, the client-first message, then the client-final message
		// (base64 of "c=biws,r=...,p=..."), which needs the derived key.
		return len(lines) >= 4 && strings.HasPrefix(lines[1], "AUTH SCRAM-SHA-256") && lines[3] != "*"
	}
	if !sentFinal(smallLines) {
		t.Fatalf("harness: the SCRAM dialogue did not reach the client-final message: %q", smallLines)
	}
	if !sentFinal(bigLines) {
		t.Fatalf("go-mail refused i=4096000 (lines %q): finding fixed", bigLines)
	}
	if big < 50*small {
		t.Fatalf("i=4096000 took %v, i=4096 took %v: the iteration count no longer drives the cost", big, small)
	}
	t.Logf("i=4096: %v, i=4096000: %v", small, big)
}
