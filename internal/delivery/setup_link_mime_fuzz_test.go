package delivery

import (
	"bytes"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

const fuzzFrom = "keyorix@example.com"

// buildSetupLinkRaw renders req exactly as DeliverSetupLink does before it
// dials (SMTPDelivery.buildMessage, then the go-mail writer). It is the seam a
// red-proof swaps.
var buildSetupLinkRaw = func(req SetupLinkRequest) ([]byte, error) {
	d := &SMTPDelivery{cfg: SMTPSettings{Host: "relay.test", From: fuzzFrom}}
	m, err := d.buildMessage(req)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FuzzSetupLinkEmailMIMERoundTrip renders the setup-link email through
// keyorix's own SMTPDelivery.buildMessage (wneessen/go-mail v0.8.2: To,
// Subject, a text/plain body and a text/html alternative) and parses the bytes
// back with the standard library (net/mail, mime, mime/multipart,
// mime/quotedprintable) and golang.org/x/net/html. The live caller
// (core.deliverSetupLink) fills RecipientEmail from the subject's email (admin,
// SCIM or SSO supplied), DisplayName from the user's display name (same
// sources), AssignmentSummary from invitation project/role names, and Link
// from the configured base URL plus a server-generated token. The setup link is
// a credential, so caller data must stay data.
//
//   - M1 FRAMING: CRLF only, no NUL, no line over 998 octets outside the known
//     unbreakable-header-word case (LF1-GOMAIL-long-header-word).
//   - M2 HEADER SET: the same header fields, each the same number of times, as
//     a benign message. An injected Bcc: or a second Content-Type fails.
//   - M3 ADDRESS: To parses back to exactly the recipient's addr-spec; From is
//     the configured sender.
//   - M4 SUBJECT: the Subject decodes (RFC 2047) back to subjectFor(req), up to
//     folding whitespace; encoded-word lookalikes in the install name are skipped.
//   - M5 MIME: the body is multipart/alternative with exactly two parts,
//     text/plain then text/html, and each decodes back to renderBody's output
//     (line breaks as CRLF; the stdlib QP stale-CR case LF1-QP-stale-cr is
//     accepted only as its exact modelled output).
//   - M6 HTML STRUCTURE: the HTML part tokenizes to the same tag/attribute
//     skeleton as a benign rendering with the same optional sections, the one
//     anchor's href is exactly the link, and the text content is exactly the
//     benign text with the caller fields substituted back in: no field can add,
//     remove or reshape an element.
//
// What this does NOT verify: the SMTP dialogue and DATA dot-stuffing (see
// FuzzSetupLinkSMTPWireRoundTrip); how a mail client renders the HTML (only
// the x/net/html tokenizer's reading of it); Date, Message-ID and the boundary
// value; display names in To (the live caller passes a bare address); whether a
// relay accepts non-ASCII addresses; InstallName and Message reach (no live
// caller sets them today, they are fuzzed anyway). Each field is capped at
// 2 KiB, the recipient at 254 octets.
func FuzzSetupLinkEmailMIMERoundTrip(f *testing.F) {
	for _, s := range [][6]string{
		{"alice@example.com", "Alice", "", "", "", "https://k.example/auth/setup/abc"},
		{"bob@example.com", "", "Acme Vault", "editor on payments", "welcome", "https://k/auth/setup/x?y=1&z=2"},
		{"a@example.com", "<script>alert(1)</script>", "", "<b>x</b>", "</p><a href=\"https://evil\">", "https://k/s\" onmouseover=\"x"},
		{"a@example.com", "x\r\nBcc: evil@example.com", "y\r\nContent-Type: text/html", "", "", "https://k/s"},
		{"a@example.com\r\nBcc: e@example.com", "n", "", "", "", "https://k/s"},
		{"a@example.com", "ünïcödé", "Ключ", "role=admin; scope=*", "line1\rline2\n.\r\n..", "https://k/s"},
		{"a@example.com", "&amp; &lt;", "=?utf-8?q?spoof?=", "", "\x00nul", "javascript:alert(1)"},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4], s[5])
	}
	f.Fuzz(func(t *testing.T, rcpt, display, install, summary, note, link string) {
		if len(rcpt) > 254 || len(display) > 2<<10 || len(install) > 2<<10 || len(summary) > 2<<10 || len(note) > 2<<10 || len(link) > 2<<10 {
			return
		}
		if rcpt == "" || link == "" {
			return // DeliverSetupLink refuses these before building
		}
		req := SetupLinkRequest{RecipientEmail: rcpt, DisplayName: display, InstallName: install, AssignmentSummary: summary, Message: note, Link: link}
		raw, err := buildSetupLinkRaw(req)
		if err != nil {
			if _, perr := mail.ParseAddress(rcpt); perr == nil {
				t.Fatalf("M3 ADDRESS: buildMessage rejected %q (%v) though net/mail parses it", rcpt, err)
			}
			return // DeliverSetupLink degrades to manual relay
		}
		checkSetupLinkMessage(t, raw, req)
	})
}

// checkSetupLinkMessage applies M1-M6 to a rendered (or received) setup-link
// email.
func checkSetupLinkMessage(t *testing.T, raw []byte, req SetupLinkRequest) {
	t.Helper()
	ctx := func() string {
		return "\n req=" + strings.ReplaceAll(strings.ReplaceAll(fmtReq(req), "\r", `\r`), "\n", `\n`) + "\n raw=" + truncQ(raw)
	}

	// M1 framing.
	for i, c := range raw {
		switch {
		case c == 0:
			t.Fatalf("M1 FRAMING: NUL at byte %d%s", i, ctx())
		case c == '\n' && (i == 0 || raw[i-1] != '\r'):
			t.Fatalf("M1 FRAMING: bare LF at byte %d%s", i, ctx())
		case c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n'):
			t.Fatalf("M1 FRAMING: bare CR at byte %d%s", i, ctx())
		}
	}
	inHeader := true
	for line := range bytes.SplitSeq(raw, []byte("\r\n")) {
		if len(line) == 0 {
			inHeader = false
		}
		if len(line) > 998 && !(inHeader && unbreakableHeaderLine(line)) {
			t.Fatalf("M1 FRAMING: %d-octet line%s", len(line), ctx())
		}
	}

	// M2 header set.
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("M2 HEADER SET: message does not parse: %v%s", err, ctx())
	}
	if got, want := headerShape(msg.Header), benignSetupLinkHeaderShape(t); !maps.Equal(got, want) {
		t.Fatalf("M2 HEADER SET: header fields %v, a benign message has %v%s", got, want, ctx())
	}

	// M3 address.
	wantRcpt, _ := mail.ParseAddress(req.RecipientEmail)
	tos, err := msg.Header.AddressList("To")
	if err != nil || len(tos) != 1 || wantRcpt == nil || tos[0].Address != wantRcpt.Address {
		t.Fatalf("M3 ADDRESS: To %q parses to %v (err %v), want exactly %v%s", msg.Header.Get("To"), tos, err, wantRcpt, ctx())
	}
	froms, err := msg.Header.AddressList("From")
	if err != nil || len(froms) != 1 || froms[0].Address != fuzzFrom {
		t.Fatalf("M3 ADDRESS: From %q parses to %v (err %v)%s", msg.Header.Get("From"), froms, err, ctx())
	}

	// M4 subject.
	if !encodedWordLookalike.MatchString(req.InstallName) {
		got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
		if err != nil || normFolding(got) != normFolding(subjectFor(req)) {
			t.Fatalf("M4 SUBJECT: Subject %q decodes to %q (err %v), want %q%s", msg.Header.Get("Subject"), got, err, subjectFor(req), ctx())
		}
	}

	// M5 MIME structure.
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" || params["boundary"] == "" {
		t.Fatalf("M5 MIME: Content-Type %q (%v)%s", msg.Header.Get("Content-Type"), err, ctx())
	}
	plain, htmlBody := renderBody(req)
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts []string
	var decoded [][]byte
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("M5 MIME: part %d: %v%s", len(parts), err, ctx())
		}
		ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		parts = append(parts, ct)
		var r io.Reader = p
		if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
			r = quotedprintable.NewReader(p)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("M5 MIME: part %d (%s) does not decode: %v%s", len(parts), ct, err, ctx())
		}
		decoded = append(decoded, b)
	}
	if len(parts) != 2 || parts[0] != "text/plain" || parts[1] != "text/html" {
		t.Fatalf("M5 MIME: parts %v, want [text/plain text/html]%s", parts, ctx())
	}
	htmlStale := false
	for i, want := range []string{plain, htmlBody} {
		got := strings.TrimSuffix(string(decoded[i]), "\r\n")
		exact := got == strings.TrimSuffix(crlfLineBreaks(want), "\r\n")
		if !exact && got != strings.TrimSuffix(qpStaleCRLineBreaks(want), "\r\n") {
			t.Fatalf("M5 MIME: %s part decodes to %q, want %q%s", parts[i], got, crlfLineBreaks(want), ctx())
		}
		htmlStale = i == 1 && !exact
	}

	// M6 HTML structure. When M5 matched the HTML part only in its
	// LF1-QP-stale-cr form, the fields are compared in that form too: the
	// template around them has no line break, so the model applies per field.
	transport := func(s string) string { return s }
	if htmlStale {
		transport = qpStaleCRLineBreaks
	}
	checkSetupLinkHTML(t, string(decoded[1]), req, transport, ctx)
}

// htmlPlaceholders stand in for the caller fields in the benign rendering M6
// compares against. They contain no HTML-special byte, so html.EscapeString
// leaves them as they are.
var htmlPlaceholders = [...]string{"QZXdisplayQZX", "QZXinstallQZX", "QZXsummaryQZX", "QZXnoteQZX", "QZXlinkQZX"}

func checkSetupLinkHTML(t *testing.T, got string, req SetupLinkRequest, transport func(string) string, ctx func() string) {
	t.Helper()
	benign := req
	fields := []*string{&benign.DisplayName, &benign.InstallName, &benign.AssignmentSummary, &benign.Message, &benign.Link}
	vals := []string{transport(req.DisplayName), transport(req.InstallName), transport(req.AssignmentSummary), transport(req.Message), transport(req.Link)}
	// Defaults (Hi there / Keyorix) apply to an empty field in both renderings.
	for i, p := range fields {
		if *p != "" {
			*p = htmlPlaceholders[i]
		}
	}
	_, benignHTML := renderBody(benign)
	wantSkel, wantText, wantHrefs := htmlSkeleton(benignHTML)
	gotSkel, gotText, gotHrefs := htmlSkeleton(got)
	if !slicesEqual(gotSkel, wantSkel) {
		t.Fatalf("M6 HTML STRUCTURE: skeleton %v, benign %v%s", gotSkel, wantSkel, ctx())
	}
	r := strings.NewReplacer(
		htmlPlaceholders[0], normHTMLText(vals[0]), htmlPlaceholders[1], normHTMLText(vals[1]),
		htmlPlaceholders[2], normHTMLText(vals[2]), htmlPlaceholders[3], normHTMLText(vals[3]),
		htmlPlaceholders[4], normHTMLText(vals[4]))
	if want := r.Replace(wantText); gotText != want {
		t.Fatalf("M6 HTML STRUCTURE: text %q, want %q%s", gotText, want, ctx())
	}
	if len(gotHrefs) != 1 || len(wantHrefs) != 1 || gotHrefs[0] != normHTMLText(vals[4]) {
		t.Fatalf("M6 HTML STRUCTURE: hrefs %q, want exactly [%q]%s", gotHrefs, req.Link, ctx())
	}
}

// normHTMLText is what the x/net/html tokenizer reports for a string that was
// written escaped: CRLF and lone CR become LF and NUL becomes U+FFFD.
func normHTMLText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\x00", "�")
}

// htmlSkeleton tokenizes s and returns the tag/attribute-name sequence, the
// concatenated text, and every href value.
func htmlSkeleton(s string) (skel []string, text string, hrefs []string) {
	z := html.NewTokenizer(strings.NewReader(normHTMLText(s)))
	var sb strings.Builder
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return skel, sb.String(), hrefs
		case html.TextToken:
			sb.Write(z.Text())
		case html.StartTagToken, html.EndTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			e := tt.String() + ":" + tok.Data
			for _, a := range tok.Attr {
				e += " " + a.Key
				if a.Key == "href" {
					hrefs = append(hrefs, a.Val)
				}
			}
			skel = append(skel, e)
		default:
			skel = append(skel, tt.String())
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func benignSetupLinkHeaderShape(t *testing.T) map[string]int {
	t.Helper()
	raw, err := buildSetupLinkRaw(SetupLinkRequest{RecipientEmail: "a@example.com", Link: "https://k/s"})
	if err != nil {
		t.Fatalf("harness: benign message failed to build: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("harness: benign message does not parse: %v", err)
	}
	return headerShape(msg.Header)
}

func fmtReq(r SetupLinkRequest) string {
	return "{rcpt=" + r.RecipientEmail + " display=" + r.DisplayName + " install=" + r.InstallName +
		" summary=" + r.AssignmentSummary + " note=" + r.Message + " link=" + r.Link + "}"
}

func truncQ(b []byte) string {
	if len(b) > 1500 {
		b = b[:1500]
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "\r", `\r`), "\n", `\n`)
}

// The helpers below model two findings of the sibling LF1 campaign
// (fuzz/leaf-libs, internal/libconformance) so this package's oracles accept
// them only in their exact modelled form. They are restated here, not imported:
// they live in another package's tests.

// encodedWordLookalike matches an RFC 2047 encoded word. mime.WordEncoder
// leaves a plain-ASCII value of that shape unencoded, so a reader decodes it:
// a display-spoofing limit, not an injection.
var encodedWordLookalike = regexp.MustCompile(`=\?[^?\s]*\?[bBqQ]\?[^?\s]*\?=`)

var foldingWS = regexp.MustCompile(`[ \t]+`)

func normFolding(s string) string { return strings.TrimSpace(foldingWS.ReplaceAllString(s, " ")) }

var headerNamePrefix = regexp.MustCompile(`^[!-9;-~]+: `)

// unbreakableHeaderLine models LF1-GOMAIL-long-header-word: go-mail folds
// header values only at spaces, so one word longer than the line limit is
// written as one over-long line. Only a line with no fold point qualifies.
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

func headerShape(h mail.Header) map[string]int {
	out := map[string]int{}
	for k, v := range h {
		out[k] = len(v)
	}
	return out
}

// qpStaleCRLineBreaks models LF1-QP-stale-cr (mime/quotedprintable.Writer,
// go1.27.3): after '\r', a byte the writer escapes as =XX does not clear the
// pending-CR flag, so the next '\n' is swallowed.
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
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// crlfLineBreaks rewrites every line break (CRLF, lone LF, lone CR) as CRLF.
func crlfLineBreaks(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
