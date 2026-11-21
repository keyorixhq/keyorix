package delivery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"
)

const (
	fuzzSMTPUser = "relay-user"
	fuzzSMTPPass = "Hunter2-relay-PASSWORD"

	// smtpFuzzTimeCap bounds one send against the in-memory server. The client's
	// own timeout is smtpDialTimeout (10s, I/O deadlines only); a healthy pipe
	// dialogue completes in milliseconds.
	smtpFuzzTimeCap = 4 * time.Second
)

// smtpRelayIdle is how long the in-memory relay waits for the client's next
// line before hanging up. A variable so a findings test can wait out a client
// that is computing.
var smtpRelayIdle = 300 * time.Millisecond

// smtpScript is what the in-memory relay answers. Empty fields take the
// benign default.
type smtpScript struct {
	greeting  string   // full greeting line, default "220 relay.test ESMTP"
	ehlo      []string // EHLO extension keywords (one per 250- line)
	starttls  string   // reply to STARTTLS, default "454 TLS not available"
	authStep  []string // replies to AUTH and each continuation line, in order
	scramSalt string   // base64 salt for a SCRAM server-first message
	scramIter string   // iteration count text for a SCRAM server-first message
	mail      string   // reply to MAIL FROM
	rcpt      string   // reply to RCPT TO
	data      string   // reply to DATA
	end       string   // reply to the end-of-data "."
}

// smtpRecord is what the relay saw. Lines are the client's raw command lines
// (CRLF stripped) outside DATA; messages are dot-unstuffed DATA payloads.
type smtpRecord struct {
	mu       sync.Mutex
	lines    []string
	mailFrom []string
	rcptTo   []string
	messages [][]byte
	dataEnd  []bool // per DATA: whether the client sent the end-of-data line
	endReply []string
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// idleReader hangs up on a client that stops talking. A client with something
// to say says it at once; one that does not is waiting for more of a reply this
// relay will never send (a continuation line, a malformed code). Without this
// the client sits out its own 10 s I/O timeout and S3's time cap would measure
// a silent peer instead of the client's own work.
type idleReader struct{ c net.Conn }

func (r idleReader) Read(p []byte) (int, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(smtpRelayIdle))
	return r.c.Read(p)
}

// serveSMTP plays the relay on one end of a net.Pipe. It returns when the
// client hangs up or sends QUIT. A reply that is not a valid SMTP line is
// written as-is: hostile scripts may do that on purpose.
func serveSMTP(conn net.Conn, sc *smtpScript, rec *smtpRecord) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(smtpFuzzTimeCap))
	r := bufio.NewReaderSize(idleReader{conn}, 64<<10)
	w := func(s string) bool {
		_, err := conn.Write([]byte(s + "\r\n"))
		return err == nil
	}
	if !w(or(sc.greeting, "220 relay.test ESMTP")) {
		return
	}
	authIdx := 0
	var scramNonce string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		rec.mu.Lock()
		rec.lines = append(rec.lines, line)
		rec.mu.Unlock()
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			ext := sc.ehlo
			out := "250-relay.test"
			for _, e := range ext {
				out += "\r\n250-" + e
			}
			out += "\r\n250 OK"
			if !w(out) {
				return
			}
		case "HELO":
			if !w("250 relay.test") {
				return
			}
		case "STARTTLS":
			reply := or(sc.starttls, "454 TLS not available")
			if !w(reply) {
				return
			}
			if strings.HasPrefix(reply, "220") {
				return // the client now speaks TLS; this relay cannot
			}
		case "AUTH":
			_, initial, _ := strings.Cut(arg, " ")
			scramClientNonce(initial, &scramNonce)
			if !smtpAuthDialogue(r, w, sc, rec, &authIdx, &scramNonce) {
				return
			}
		case "MAIL":
			rec.mu.Lock()
			rec.mailFrom = append(rec.mailFrom, arg)
			rec.mu.Unlock()
			if !w(or(sc.mail, "250 OK")) {
				return
			}
		case "RCPT":
			rec.mu.Lock()
			rec.rcptTo = append(rec.rcptTo, arg)
			rec.mu.Unlock()
			if !w(or(sc.rcpt, "250 OK")) {
				return
			}
		case "DATA":
			reply := or(sc.data, "354 go ahead")
			if !w(reply) {
				return
			}
			if !strings.HasPrefix(reply, "354") {
				continue
			}
			var msg bytes.Buffer
			ended := false
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					break
				}
				if dl == ".\r\n" {
					ended = true
					break
				}
				msg.WriteString(strings.TrimPrefix(dl, "."))
			}
			end := or(sc.end, "250 queued")
			rec.mu.Lock()
			rec.messages = append(rec.messages, msg.Bytes())
			rec.dataEnd = append(rec.dataEnd, ended)
			rec.endReply = append(rec.endReply, end)
			rec.mu.Unlock()
			if !ended || !w(end) {
				return
			}
		case "RSET", "NOOP":
			if !w("250 OK") {
				return
			}
		case "QUIT":
			_ = w("221 bye")
			return
		default:
			if !w("500 unknown command") {
				return
			}
		}
	}
}

// smtpAuthDialogue answers AUTH and its continuation lines from sc.authStep.
// A step containing "{scram}" is replaced by a base64 SCRAM server-first
// message that echoes the client's nonce, so the fuzzer reaches the SCRAM
// key derivation instead of dying at the nonce check.
func smtpAuthDialogue(r *bufio.Reader, w func(string) bool, sc *smtpScript, rec *smtpRecord, idx *int, nonce *string) bool {
	for {
		step := "535 authentication failed"
		if *idx < len(sc.authStep) {
			step = sc.authStep[*idx]
		}
		*idx++
		if strings.Contains(step, "{scram}") {
			first := "r=" + *nonce + "srv,s=" + or(sc.scramSalt, "c2FsdA==") + ",i=" + or(sc.scramIter, "4096")
			step = strings.ReplaceAll(step, "{scram}", base64.StdEncoding.EncodeToString([]byte(first)))
		}
		if !w(step) {
			return false
		}
		if !strings.HasPrefix(step, "334") {
			return true
		}
		line, err := r.ReadString('\n')
		if err != nil {
			return false
		}
		line = strings.TrimRight(line, "\r\n")
		rec.mu.Lock()
		rec.lines = append(rec.lines, line)
		rec.mu.Unlock()
		scramClientNonce(line, nonce)
	}
}

// scramClientNonce records the nonce of a base64 SCRAM client-first message
// ("n,,n=user,r=<nonce>"), wherever the client sends it: go-mail sends it as
// the first continuation line, not as an AUTH initial response.
func scramClientNonce(b64 string, nonce *string) {
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || !strings.HasPrefix(string(dec), "n,") {
		return
	}
	if _, after, ok := strings.Cut(string(dec), ",r="); ok {
		*nonce, _, _ = strings.Cut(after, ",")
	}
}

// sendViaPipe sends req the way DeliverSetupLink does (SMTPDelivery.newClient,
// SMTPDelivery.buildMessage, DialAndSendWithContext) with one change: the
// client's dialer is replaced by a net.Pipe to serveSMTP, because the sandbox
// these harnesses were written in refuses loopback listeners. It returns how
// long the send took and the send error.
func sendViaPipe(t *testing.T, cfg SMTPSettings, req SetupLinkRequest, sc *smtpScript, rec *smtpRecord) (time.Duration, error) {
	t.Helper()
	d := &SMTPDelivery{cfg: cfg}
	msg, err := d.buildMessage(req)
	if err != nil {
		return 0, err
	}
	client, err := d.newClient()
	if err != nil {
		t.Fatalf("harness: newClient: %v", err)
	}
	var wg sync.WaitGroup
	var conns []net.Conn
	var mu sync.Mutex
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, s := net.Pipe()
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		wg.Go(func() { serveSMTP(s, sc, rec) })
		return c, nil
	}
	if err := mail.WithDialContextFunc(dial)(client); err != nil {
		t.Fatalf("harness: WithDialContextFunc: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), smtpFuzzTimeCap)
	defer cancel()
	start := time.Now()
	serr := client.DialAndSendWithContext(ctx, msg)
	took := time.Since(start)
	mu.Lock()
	for _, c := range conns {
		_ = c.Close()
	}
	mu.Unlock()
	wg.Wait()
	return took, serr
}

// FuzzSetupLinkSMTPWireRoundTrip sends the setup-link email through go-mail's
// SMTP client to a benign in-memory relay and parses what the relay received.
//
//   - W1 ENVELOPE: exactly one MAIL FROM, with the configured sender's
//     addr-spec, and exactly one RCPT TO, with the recipient's addr-spec. A
//     recipient that smuggles a second RCPT, or a parameter, fails.
//   - W2 COMMAND SET: every command line the client sent is one of the verbs a
//     benign send uses (EHLO/HELO, MAIL, RCPT, DATA, QUIT, RSET, NOOP); caller
//     data never starts a command line of its own.
//   - W3 DATA ROUND-TRIP: exactly one DATA payload, terminated by the client's
//     own end-of-data line, and after dot-unstuffing it passes every check of
//     FuzzSetupLinkEmailMIMERoundTrip (M1-M6). A body line "." or "\n.\n"
//     that ended DATA early (SMTP smuggling) leaves a truncated message, which
//     fails M5, or a second transaction, which fails W1.
//   - W4 SUCCESS: the send returns nil, within smtpFuzzTimeCap.
//
// What this does NOT verify: TLS (the harness relay runs tls=none and the
// client's dialer is a net.Pipe, so this does not check the starttls/implicit
// code paths or certificate checks); SMTPUTF8 and 8BITMIME negotiation (the relay
// offers neither); the config gate that requires KEYORIX_ALLOW_INSECURE_SMTP for
// tls=none (the harness builds SMTPDelivery directly); a relay's own parsing of
// the bytes. Field caps as in FuzzSetupLinkEmailMIMERoundTrip.
func FuzzSetupLinkSMTPWireRoundTrip(f *testing.F) {
	for _, s := range [][4]string{
		{"alice@example.com", "Alice", "editor on payments", "https://k.example/auth/setup/abc"},
		{"a@example.com", "x\r\n.\r\nMAIL FROM:<e@example.com>", ".\n.\r\n..\r.", "https://k/s"},
		{"a@example.com\r\nRCPT TO:<e@example.com>", "n", "", "https://k/s"},
		{"\"a> NOTIFY=NEVER\"@example.com", "n", "", "https://k/s"},
		{"a@example.com", strings.Repeat("é", 300), strings.Repeat(".", 1200), "https://k/s"},
	} {
		f.Add(s[0], s[1], s[2], s[3])
	}
	f.Fuzz(func(t *testing.T, rcpt, display, summary, link string) {
		if len(rcpt) > 254 || len(display) > 2<<10 || len(summary) > 2<<10 || len(link) > 2<<10 || rcpt == "" || link == "" {
			return
		}
		req := SetupLinkRequest{RecipientEmail: rcpt, DisplayName: display, AssignmentSummary: summary, Link: link}
		wantRcpt, perr := netmail.ParseAddress(rcpt)
		if perr != nil {
			return // buildMessage rejects it (M3 covers the agreement)
		}
		rec := &smtpRecord{}
		cfg := SMTPSettings{Host: "relay.test", Port: 2525, From: fuzzFrom, TLS: smtpTLSNone}
		took, err := sendViaPipe(t, cfg, req, &smtpScript{}, rec)
		checkSMTPWire(t, req, wantRcpt.Address, rec, err, took)
	})
}

func checkSMTPWire(t *testing.T, req SetupLinkRequest, wantRcpt string, rec *smtpRecord, err error, took time.Duration) {
	t.Helper()
	if took > smtpFuzzTimeCap {
		t.Fatalf("W4 SUCCESS: send took %v", took)
	}
	if err != nil {
		t.Fatalf("W4 SUCCESS: benign relay, send failed: %v\n lines=%q", err, rec.lines)
	}
	for _, l := range rec.lines {
		verb, _, _ := strings.Cut(l, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "RSET", "NOOP":
		default:
			t.Fatalf("W2 COMMAND SET: client sent %q\n lines=%q", l, rec.lines)
		}
	}
	if len(rec.mailFrom) != 1 || envelopeAddr(rec.mailFrom[0], "FROM:") != fuzzFrom {
		t.Fatalf("W1 ENVELOPE: MAIL commands %q, want one FROM:<%s>", rec.mailFrom, fuzzFrom)
	}
	if len(rec.rcptTo) != 1 || canonicalAddr(envelopeAddr(rec.rcptTo[0], "TO:")) != wantRcpt {
		t.Fatalf("W1 ENVELOPE: RCPT commands %q, want one TO:<%s>", rec.rcptTo, wantRcpt)
	}
	if len(rec.messages) != 1 || !rec.dataEnd[0] {
		t.Fatalf("W3 DATA ROUND-TRIP: %d DATA payloads (ended=%v)", len(rec.messages), rec.dataEnd)
	}
	checkSetupLinkMessage(t, rec.messages[0], req)
}

// canonicalAddr parses an envelope path's addr-spec (which may carry a quoted
// local part) the way net/mail does, so it compares with ParseAddress(...).Address;
// "" when it does not parse.
func canonicalAddr(spec string) string {
	if spec == "" {
		return ""
	}
	a, err := netmail.ParseAddress("<" + spec + ">")
	if err != nil {
		return ""
	}
	return a.Address
}

// envelopeAddr returns the address inside "<...>" of a MAIL/RCPT argument, and
// "" when the argument carries anything but "PREFIX<addr>" (a parameter, a
// second path, trailing bytes).
func envelopeAddr(arg, prefix string) string {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return ""
	}
	rest := arg[len(prefix):]
	if !strings.HasPrefix(rest, "<") || !strings.HasSuffix(rest, ">") {
		return ""
	}
	return rest[1 : len(rest)-1]
}

// FuzzSetupLinkHostileSMTPServer sends the setup-link email to a relay whose
// every reply is fuzzer-chosen: the greeting, the EHLO extension list
// (including AUTH mechanism lists and STARTTLS), STARTTLS, the AUTH dialogue
// (with a SCRAM server-first message that echoes the client nonce, so salt and
// iteration count are reachable), and the MAIL/RCPT/DATA/end replies. A relay
// is operator-configured, but with tls=none anyone on the path is the relay, and
// with starttls the relay itself is still a party keyorix should not hand a
// cleartext credential to.
//
//   - S1 NO CLEARTEXT PASSWORD (tls=none with a username, the
//     KEYORIX_ALLOW_INSECURE_SMTP mode): no client line carries the relay
//     password, raw or inside any base64 token. This is the property
//     internal/delivery's tls=none refusal text states (PLAIN, LOGIN and SCRAM are
//     never used without TLS: internal/smtpauth).
//   - S2 NOTHING BEFORE TLS (starttls, the default): when the relay never
//     completes TLS, the client sends no AUTH, MAIL, RCPT or DATA, so neither the
//     password nor the setup link leaves in cleartext.
//   - S3 BOUNDED WORK: one send returns within smtpFuzzTimeCap, whatever the
//     relay says (the client's own 10 s timeout bounds I/O waits, not CPU). The
//     SCRAM iteration count is part of what the relay says: without TLS SCRAM is
//     never selected, and with TLS smtpauth refuses a count above its bound
//     (#4383, TestSCRAMNotSelectedWithoutTLS).
//   - S4 SUCCESS MEANS ACCEPTED: a nil send error implies the relay received one
//     complete DATA payload and answered its end-of-data line with 2xx.
//
// What this does NOT verify: implicit TLS and real TLS handshakes (the relay
// cannot speak TLS; a "220" to STARTTLS ends the dialogue); the strength of
// challenge-response mechanisms a tls=none relay can still pick (CRAM-MD5 and
// NTLM responses are offline-guessable by whoever sees them, which is the
// documented price of tls=none, not checked here); relay replies over 64 KiB per
// line; DSN, PIPELINING and CHUNKING (go-mail does not use them here).
func FuzzSetupLinkHostileSMTPServer(f *testing.F) {
	f.Add(byte(0), "AUTH PLAIN LOGIN", "", "334 ", "", "", "250 OK")
	f.Add(byte(0), "AUTH CRAM-MD5 PLAIN", "", "334 PDEyMzQ1Ni4xMjM0QHJlbGF5Pg==\n235 ok", "", "", "250 OK")
	f.Add(byte(0), "AUTH SCRAM-SHA-256 PLAIN", "", "334 \n334 {scram}\n334 dj1ub3Bl\n235 ok", "c2FsdA==", "4096", "250 OK")
	f.Add(byte(1), "AUTH SCRAM-SHA-1", "", "334 \n334 {scram}\n235 ok", "", "1", "250 OK")
	f.Add(byte(2), "AUTH SCRAM-SHA-256", "", "334 \n334 {scram}\n235 ok", "", "-1", "250 OK")
	f.Add(byte(0), "AUTH XOAUTH2 PLAIN LOGIN NTLM", "", "334 TlRMTVNTUAACAAAAAAAAAAAAAAABAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n235 ok", "", "", "250 OK")
	f.Add(byte(1), "STARTTLS\nAUTH PLAIN", "454 no", "235 ok", "", "", "250 OK")
	f.Add(byte(1), "AUTH PLAIN", "", "235 ok", "", "", "250 OK")
	f.Add(byte(1), "STARTTLS", "220 go", "", "", "", "250 OK")
	f.Add(byte(2), "8BITMIME", "", "", "", "", "550 no")
	f.Fuzz(func(t *testing.T, mode byte, ehlo, starttls, auth, salt, iter, end string) {
		if len(ehlo)+len(starttls)+len(auth)+len(salt)+len(iter)+len(end) > 4<<10 {
			return
		}
		sc := &smtpScript{
			ehlo:      splitNonEmpty(ehlo),
			starttls:  firstLine(starttls),
			authStep:  splitNonEmpty(auth),
			scramSalt: firstLine(salt),
			scramIter: firstLine(iter),
			end:       firstLine(end),
		}
		cfg := SMTPSettings{Host: "relay.test", Port: 2525, From: fuzzFrom}
		switch mode % 3 {
		case 0:
			cfg.TLS, cfg.Username, cfg.Password = smtpTLSNone, fuzzSMTPUser, fuzzSMTPPass
		case 1:
			cfg.TLS, cfg.Username, cfg.Password = smtpTLSStartTLS, fuzzSMTPUser, fuzzSMTPPass
		default:
			cfg.TLS = smtpTLSNone
		}
		req := SetupLinkRequest{RecipientEmail: "alice@example.com", DisplayName: "Alice", Link: "https://k.example/auth/setup/SECRETTOKEN"}
		rec := &smtpRecord{}
		took, err := sendViaPipe(t, cfg, req, sc, rec)
		checkHostileSMTP(t, cfg, rec, err, took)
	})
}

func checkHostileSMTP(t *testing.T, cfg SMTPSettings, rec *smtpRecord, err error, took time.Duration) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if took > smtpFuzzTimeCap {
		t.Fatalf("S3 BOUNDED WORK: send took %v (cap %v), err=%v\n lines=%q", took, smtpFuzzTimeCap, err, rec.lines)
	}
	if cfg.Password != "" {
		for _, l := range rec.lines {
			if leaksSecret(l, cfg.Password) {
				t.Fatalf("S1/S2 CLEARTEXT PASSWORD: client line %q carries the relay password (tls=%s)\n lines=%q", l, cfg.TLS, rec.lines)
			}
		}
	}
	if cfg.TLS == smtpTLSStartTLS {
		for _, l := range rec.lines {
			verb, _, _ := strings.Cut(l, " ")
			switch strings.ToUpper(verb) {
			case "AUTH", "MAIL", "RCPT", "DATA":
				t.Fatalf("S2 NOTHING BEFORE TLS: client sent %q on a connection that never completed TLS\n lines=%q", l, rec.lines)
			}
		}
		if len(rec.messages) != 0 {
			t.Fatalf("S2 NOTHING BEFORE TLS: setup-link message sent in cleartext")
		}
	}
	if err == nil {
		if len(rec.messages) != 1 || !rec.dataEnd[0] || !strings.HasPrefix(rec.endReply[0], "2") {
			t.Fatalf("S4 SUCCESS MEANS ACCEPTED: send returned nil; DATA payloads=%d ended=%v end replies=%q", len(rec.messages), rec.dataEnd, rec.endReply)
		}
	}
	if err != nil && errors.Is(err, context.DeadlineExceeded) && took < smtpFuzzTimeCap/2 {
		t.Fatalf("harness: deadline error after only %v", took)
	}
}

// leaksSecret reports whether line carries secret raw, or inside any
// whitespace-separated token that base64-decodes (std or raw-std) to bytes
// containing it.
func leaksSecret(line, secret string) bool {
	if strings.Contains(line, secret) {
		return true
	}
	for tok := range strings.FieldsSeq(line) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if b, err := enc.DecodeString(tok); err == nil && bytes.Contains(b, []byte(secret)) {
				return true
			}
		}
	}
	return false
}

func splitNonEmpty(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return strings.TrimRight(l, "\r")
}
