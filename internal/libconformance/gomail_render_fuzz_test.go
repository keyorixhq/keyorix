package libconformance

import (
	"bytes"
	"io"
	"maps"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"

	gomail "github.com/wneessen/go-mail"
)

// FuzzGoMailRenderRoundTrip pins what keyorix relies on when wneessen/go-mail renders a
// message from caller data. internal/notifychan's EmailSink.send builds exactly this
// shape: To(ev.Email), Subject(ev.Title), one text/plain body from ev.Message, and
// internal/delivery's setup-link mailer does the same with an install name in the
// subject. Titles and messages embed user-chosen names and free text, so the rendered
// bytes must carry them as data, never as message structure.
//
//   - O1 HEADER SET: the rendered message has exactly the header fields a benign message
//     has, each once. An extra field (an injected Bcc:, a second Subject:) fails.
//   - O2 ADDRESS: when To accepts the recipient, the To header parses back to exactly
//     that one address (same addr-spec, same display name), and the envelope recipient
//     (GetRecipients, what RCPT TO sends) parses back to the same addr-spec and has no
//     CR, LF or NUL.
//   - O3 SUBJECT: the Subject header decodes (RFC 2047) back to the subject, up to
//     folding whitespace (runs of space/tab compare as one space, ends trimmed).
//     Plain-ASCII subjects that themselves look like encoded words are a named
//     exception (xmailEncodedWordLookalike): mime.WordEncoder leaves them unencoded,
//     so a reader decodes them. That is a display-spoofing limit, not an injection.
//   - O4 BODY: the quoted-printable body decodes back to the body, with every line
//     break as CRLF.
//   - O5 SMTP FRAMING: the whole message uses CRLF only (no bare CR or LF, the
//     precondition for SMTP smuggling), has no NUL, and no line over 998 octets
//     (RFC 5322 §2.1.1).
//
// What this does NOT verify: SMTP DATA dot-stuffing and the wire dialogue (go-mail's
// smtp client, which this target never dials); multipart/alternative bodies (the
// setup-link mailer's HTML part); DKIM, S/MIME, attachments; Date and Message-ID
// values; display rendering of non-ASCII names; whether a real SMTP server accepts a
// quoted local part or a non-ASCII address (the envelope check is a parse round-trip,
// not SMTPUTF8 conformance). Inputs are capped at 4 KiB each.
func FuzzGoMailRenderRoundTrip(f *testing.F) {
	for _, s := range [][3]string{
		{"alice@example.com", "Access request for project payments", "bob asked for read access.\n\nOpen in Keyorix: https://k/x\n\n— Keyorix\n"},
		{"Alice <alice@example.com>", "Set up your Keyorix access", "line1\r\nline2\n"},
		{"alice@example.com", "a\r\nBcc: evil@example.com", "x"},
		{"alice@example.com\r\nBcc: evil@example.com", "s", "b"},
		{`"a> NOTIFY=NEVER"@example.com`, "s", "b"},
		{"=?utf-8?q?=E2=9C=93?= <a@example.com>", "=?utf-8?q?spoof?=", "b"},
		{"alice@example.com", strings.Repeat("x", 1200), "y"},
		{"alice@example.com", "ünïcödé " + strings.Repeat("é", 200), "body\r.\n.\r\n..\n"},
		{"alice@example.com", "tab\there  double  space", strings.Repeat("z", 2000)},
		{"a@[127.0.0.1]", "", ""},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, rcpt, subject, body string) {
		if len(rcpt) > 4<<10 || len(subject) > 4<<10 || len(body) > 4<<10 {
			return
		}
		checkGoMailRender(t, rcpt, subject, body, newGoMailMsg)
	})
}

// newGoMailMsg is the seam a red-proof swaps: it renders the notifychan shape.
var newGoMailMsg = func(rcpt, subject, body string) (*gomail.Msg, error) {
	m := gomail.NewMsg()
	if err := m.From("keyorix@example.com"); err != nil {
		return nil, err
	}
	if err := m.To(rcpt); err != nil {
		return nil, err
	}
	m.Subject(subject)
	m.SetBodyString(gomail.TypeTextPlain, body)
	return m, nil
}

type goMailBuilder func(rcpt, subject, body string) (*gomail.Msg, error)

// xmailEncodedWordLookalike matches any string that looks like an RFC 2047 encoded word
// (=?charset?encoding?encoded-text?=). The encoded-text field may contain spaces
// (a malformed encoded word); mime.WordDecoder will attempt to parse it and may fail
// (e.g. "mime: unhandled charset """). That failure is not an injection — the oracle
// comment explicitly says "which may decode it or, for an unknown charset, fail to.
// Neither is an injection, so O3 does not judge it." The encoded-text field is `.*?` (not
// `[^?]*`): mime.WordDecoder ends the word at the first "?=", so '?' inside the text is
// legal and malformed variants like `=??q? ?=` and `=??q???=` are skipped too
// (fuzz-corpus#198, same fix as the setup-link MIME oracle, keyorix#4746).
var xmailEncodedWordLookalike = regexp.MustCompile(`=\?[^?]*\?[bBqQ]\?.*?\?=`)

var foldingWS = regexp.MustCompile(`[ \t]+`)

func normFolding(s string) string { return strings.TrimSpace(foldingWS.ReplaceAllString(s, " ")) }

// xmailStdlibCannotRoundTripAddress reports whether the To header is exactly what net/mail
// formats for want and net/mail itself cannot parse that text back (golang/go#80592). It is
// false for any header the standard library can read, and for any header that differs from
// the library's own rendering.
func xmailStdlibCannotRoundTripAddress(want *mail.Address, header string) bool {
	if want == nil || !strings.Contains(want.Name, `\`) {
		return false
	}
	if header != want.String() {
		return false
	}
	_, err := mail.ParseAddress(header)
	return err != nil
}

func checkGoMailRender(t *testing.T, rcpt, subject, body string, build goMailBuilder) {
	t.Helper()
	baseline := renderGoMail(t, build, "a@example.com", "s", "b")
	if baseline == nil {
		t.Fatal("harness: benign message failed to build")
	}
	wantRcpt, rcptErr := mail.ParseAddress(rcpt)
	m, err := build(rcpt, subject, body)
	if err != nil {
		if rcptErr == nil {
			t.Fatalf("O2 ADDRESS: go-mail rejected %q (%v) though net/mail parses it", rcpt, err)
		}
		return // rejected recipient: nothing is rendered or sent
	}
	if rcptErr != nil {
		t.Fatalf("O2 ADDRESS: go-mail accepted %q though net/mail rejects it (%v)", rcpt, rcptErr)
	}
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatalf("harness: WriteTo failed: %v", err)
	}
	raw := buf.Bytes()

	// O5 framing.
	for i, c := range raw {
		switch {
		case c == 0:
			t.Fatalf("O5 FRAMING: NUL at byte %d\n rcpt=%q subject=%q body=%q", i, rcpt, subject, body)
		case c == '\n' && (i == 0 || raw[i-1] != '\r'):
			t.Fatalf("O5 FRAMING: bare LF at byte %d\n rcpt=%q subject=%q body=%q\n msg=%q", i, rcpt, subject, body, raw)
		case c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n'):
			t.Fatalf("O5 FRAMING: bare CR at byte %d\n rcpt=%q subject=%q body=%q\n msg=%q", i, rcpt, subject, body, raw)
		}
	}
	inHeader := true
	for line := range bytes.SplitSeq(raw, []byte("\r\n")) {
		if len(line) == 0 {
			inHeader = false
		}
		if len(line) > 998 && !(inHeader && unbreakableHeaderLine(line)) {
			t.Fatalf("O5 FRAMING: %d-octet line (limit 998)\n rcpt=%q subject=%q body=%q\n line=%.120q...", len(line), rcpt, subject, body, line)
		}
	}

	// O1 header set.
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("O1 HEADER SET: rendered message does not parse: %v\n msg=%q", err, raw)
	}
	if got, want := headerShape(msg.Header), headerShape(baseline.Header); !maps.Equal(got, want) {
		t.Fatalf("O1 HEADER SET: header fields %v, a benign message has %v\n rcpt=%q subject=%q body=%q\n msg=%q", got, want, rcpt, subject, body, raw)
	}

	// O2 address.
	tos, err := msg.Header.AddressList("To")
	if err != nil && xmailStdlibCannotRoundTripAddress(wantRcpt, msg.Header.Get("To")) {
		// golang/go#80592: net/mail.Address.String Q-encodes a display name holding a
		// backslash with the backslash left raw, which AddressList then rejects. The header
		// is exactly what the standard library itself formats, so this is its defect, not
		// go-mail's. Only this exact shape is waived; O1 still pins the header set. Same
		// waiver as stdlibCannotRoundTripAddress in internal/delivery/setup_link_mime_fuzz_test.go
		// (keep the two in step).
		tos, err = []*mail.Address{wantRcpt}, nil
	}
	if err != nil || len(tos) != 1 || tos[0].Address != wantRcpt.Address || tos[0].Name != wantRcpt.Name {
		t.Fatalf("O2 ADDRESS: To header %q parses to %v (err %v), want exactly %#v", msg.Header.Get("To"), tos, err, *wantRcpt)
	}
	rcpts, err := m.GetRecipients()
	if err != nil || len(rcpts) != 1 {
		t.Fatalf("O2 ADDRESS: GetRecipients = %q, %v", rcpts, err)
	}
	if strings.ContainsAny(rcpts[0], "\r\n\x00") {
		t.Fatalf("O2 ADDRESS: envelope recipient %q carries CR/LF/NUL", rcpts[0])
	}
	if env, err := mail.ParseAddress(rcpts[0]); err != nil || env.Address != wantRcpt.Address || env.Name != "" {
		t.Fatalf("O2 ADDRESS: envelope recipient %q parses to %v (err %v), want addr-spec %q", rcpts[0], env, err, wantRcpt.Address)
	}

	// O3 subject.
	// A plain subject that itself contains an encoded-word shape is the named exception:
	// it reaches the reader verbatim, which may decode it or, for an unknown charset,
	// fail to. Neither is an injection, so O3 does not judge it.
	if !xmailEncodedWordLookalike.MatchString(subject) {
		gotSubj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
		if err != nil {
			t.Fatalf("O3 SUBJECT: Subject header %q does not decode: %v", msg.Header.Get("Subject"), err)
		}
		if normFolding(gotSubj) != normFolding(subject) {
			t.Fatalf("O3 SUBJECT: subject %q renders as %q and decodes to %q", subject, msg.Header.Get("Subject"), gotSubj)
		}
	}

	// O4 body.
	if cte := msg.Header.Get("Content-Transfer-Encoding"); cte != "quoted-printable" {
		t.Fatalf("harness: unexpected Content-Transfer-Encoding %q", cte)
	}
	gotBody, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatalf("O4 BODY: quoted-printable body does not decode: %v\n msg=%q", err, raw)
	}
	if want := crlfLineBreaks(body); string(gotBody) != want && string(gotBody) != qpStaleCRLineBreaks(body) {
		t.Fatalf("O4 BODY: body %q decodes back as %q, want %q", body, gotBody, want)
	}
}

func renderGoMail(t *testing.T, build goMailBuilder, rcpt, subject, body string) *mail.Message {
	t.Helper()
	m, err := build(rcpt, subject, body)
	if err != nil {
		return nil
	}
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		return nil
	}
	msg, err := mail.ReadMessage(&buf)
	if err != nil {
		return nil
	}
	return msg
}

var headerNamePrefix = regexp.MustCompile(`^[!-9;-~]+: `)

// unbreakableHeaderLine models finding LF1-GOMAIL-long-header-word: go-mail folds
// header values only at spaces, so one word longer than the line limit (a long ASCII
// subject token, a long addr-spec) is written as one over-long line. A line is that
// known case when, after the leading fold whitespace or the "Name: " prefix, it holds
// no space or tab: no legal fold point existed. A long line that still contains a fold
// point, or any long body line, is a new defect. TestGoMailFindingLongHeaderWord goes
// red when go-mail starts breaking such words.
func unbreakableHeaderLine(line []byte) bool {
	rest := bytes.TrimLeft(line, " \t")
	if len(rest) == len(line) {
		loc := headerNamePrefix.FindIndex(line)
		if loc == nil {
			return false
		}
		rest = line[loc[1]:]
	}
	return !bytes.ContainsAny(rest, " \t")
}

// headerShape counts each header field name.
func headerShape(h mail.Header) map[string]int {
	out := map[string]int{}
	for k, v := range h {
		out[k] = len(v)
	}
	return out
}

// qpStaleCRLineBreaks models finding LF1-QP-stale-cr (Go standard library,
// mime/quotedprintable.Writer, seen on go1.27.3): Write sets a pending-CR flag on '\r'
// so that a following '\n' is not doubled, and clears it on every byte copied
// literally, but not on a byte it has to escape as =XX. So "\r", an escaped byte
// (control, '=', non-ASCII), then "\n" loses that "\n": "a\r=\nb" decodes as
// "a\r\n=b". This returns the body as that writer actually carries it; O4 accepts it
// only as this exact output, so any other body change still fails.
// TestQPFindingStaleCR goes red when the standard library is fixed.
func qpStaleCRLineBreaks(s string) string {
	var sb strings.Builder
	cr := false
	for i := range len(s) {
		b := s[i]
		switch {
		case b == '\n' && cr:
			cr = false
		case b == '\r' || b == '\n':
			sb.WriteString("\r\n")
			cr = b == '\r'
		case (b >= '!' && b <= '~' && b != '=') || b == ' ' || b == '\t':
			sb.WriteByte(b)
			cr = false
		default:
			sb.WriteByte(b) // escaped as =XX; the pending CR survives
		}
	}
	return sb.String()
}

// crlfLineBreaks rewrites every line break (CRLF, lone LF, lone CR) as CRLF, which is
// how a text/plain body is carried.
func crlfLineBreaks(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
