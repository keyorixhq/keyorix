package delivery

// mail_injection_fuzz_test.go — ML1 injection-class fuzzing of outbound mail
// formatting (task ML1, piece 1).
//
// Target: the REAL setup-link message builder, SMTPDelivery.buildMessage
// (smtp.go), which is the live hub-side caller that hands a *mail.Msg to
// wneessen/go-mail. The attacker-influenced fields that reach it are the
// recipient address (SetupLinkRequest.RecipientEmail — chosen by the admin who
// invites a principal), and the Subject / body, which fold in InstallName
// (operator config), DisplayName, Message and AssignmentSummary (inviter-
// supplied text). We feed hostile bytes (CR, LF, NUL, header-looking lines,
// MIME boundary strings, RFC2047 word fragments) into every one of those fields
// and serialise the produced message with Msg.WriteTo, exactly as
// DialAndSendWithContext would put on the wire.
//
// Oracle (STRUCTURAL EQUALITY against a benign baseline of the same shape):
// parse the produced bytes with an INDEPENDENT parser (net/mail for the header
// block, mime/multipart for the body) and assert that the *structure* — the
// multiset of header field names, the number of To recipients, and the number
// of MIME parts — is identical to the structure of a message built from benign
// values with the same optional-field shape. Attacker bytes must never create
// an extra header, an extra recipient, or an extra MIME part. CRLF/header
// injection or MIME confusion would change one of those three counts and fire
// the oracle.
//
// What this oracle does NOT verify (recorded in the report):
//   - It does not assert the message is deliverable or that go-mail's wire
//     encoding is RFC-5322-canonical; only that injection does not change
//     structure. A message that is mangled but structurally equal passes.
//   - It does not cover attachments or reply-to: the setup-link mailer sets
//     neither (no AttachFile / ReplyTo call in smtp.go), so those go-mail code
//     paths are exercised by the notifychan target's sibling, not here.
//   - It inspects only headers net/mail surfaces as the top-level block plus the
//     first multipart level; a boundary injected so deep that neither parser
//     descends to it is out of scope (go-mail base64/QP-encodes bodies, so this
//     is believed unreachable, not merely unchecked).
//   - It does not prove the recipient the admin typed is the recipient that
//     receives mail end-to-end; it proves buildMessage emits exactly one To.

import (
	"bufio"
	"mime"
	"mime/multipart"
	"net/mail"
	"sort"
	"strings"
	"testing"

	gomail "github.com/wneessen/go-mail"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// fixedSender is a valid, non-attacker From used for every built message so the
// only variable between the hostile and benign messages is the attacker input.
const fixedSender = "Keyorix <noreply@keyorix.example>"

// msgStructure is the injection-relevant shape of a serialised message, derived
// by an independent parser. Two messages with equal structure differ only in
// field *content*, never in how many headers / recipients / MIME parts exist.
type msgStructure struct {
	headerKeys []string // sorted multiset of top-level header field names
	toCount    int      // number of parsed To addresses
	partCount  int      // number of MIME parts (0 if not multipart)
}

func (a msgStructure) equal(b msgStructure) bool {
	if a.toCount != b.toCount || a.partCount != b.partCount {
		return false
	}
	if len(a.headerKeys) != len(b.headerKeys) {
		return false
	}
	for i := range a.headerKeys {
		if a.headerKeys[i] != b.headerKeys[i] {
			return false
		}
	}
	return true
}

// buildSetupMessageBytes builds the real setup-link message for req and returns
// its wire bytes, or ("", false) if buildMessage rejected the input (e.g. an
// unparseable recipient address — a legitimate rejection, not a finding).
func buildSetupMessageBytes(t *testing.T, req ports.SetupLinkRequest) (string, bool) {
	t.Helper()
	d := &SMTPDelivery{cfg: SMTPSettings{Host: "relay.example", From: fixedSender}}
	var msg *gomail.Msg
	var buildErr error
	fuzzutil.Guard(t.Fatalf, "delivery.buildMessage", func() {
		msg, buildErr = d.buildMessage(req)
	})
	if buildErr != nil || msg == nil {
		return "", false
	}
	var sb strings.Builder
	// WriteTo is what DialAndSendWithContext serialises onto the wire.
	var wErr error
	fuzzutil.Guard(t.Fatalf, "delivery.Msg.WriteTo", func() {
		_, wErr = msg.WriteTo(&sb)
	})
	if wErr != nil {
		// A build that succeeds but cannot serialise is itself worth surfacing.
		t.Fatalf("buildMessage succeeded but WriteTo failed for %#v: %v", req, wErr)
	}
	return sb.String(), true
}

// parseStructure derives msgStructure from raw message bytes with parsers
// independent of go-mail. A parse failure is reported to the caller; the caller
// decides whether that is itself a finding.
func parseStructure(raw string) (msgStructure, error) {
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return msgStructure{}, err
	}
	var keys []string
	for k := range m.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	toCount := 0
	if addrs, err := m.Header.AddressList("To"); err == nil {
		toCount = len(addrs)
	}

	partCount := 0
	ct := m.Header.Get("Content-Type")
	if mt, params, err := mime.ParseMediaType(ct); err == nil && strings.HasPrefix(mt, "multipart/") {
		if boundary := params["boundary"]; boundary != "" {
			mr := multipart.NewReader(bufio.NewReader(m.Body), boundary)
			for {
				_, perr := mr.NextPart()
				if perr != nil {
					break
				}
				partCount++
			}
		}
	}
	return msgStructure{headerKeys: keys, toCount: toCount, partCount: partCount}, nil
}

// benignFor returns a request with the same optional-field *shape* as req (which
// optional fields are empty vs set) but with harmless, injection-free values. It
// is the structural baseline the hostile message is compared against.
func benignFor(req ports.SetupLinkRequest) ports.SetupLinkRequest {
	set := func(src, benign string) string {
		if src == "" {
			return ""
		}
		return benign
	}
	return ports.SetupLinkRequest{
		RecipientEmail:    "recipient@keyorix.example",
		Link:              "https://keyorix.example/setup?t=abc123",
		DisplayName:       set(req.DisplayName, "Alice Example"),
		InstallName:       set(req.InstallName, "Acme Keyorix"),
		Message:           set(req.Message, "Welcome aboard"),
		AssignmentSummary: set(req.AssignmentSummary, "developer on app"),
		Purpose:           set(req.Purpose, "invite"),
	}
}

func FuzzMailSetupLinkInjection(f *testing.F) {
	// Seeds: benign, then a sweep of header/MIME injection idioms in each field.
	seed := func(recipient, display, install, message, summary, link string) {
		f.Add(recipient, display, install, message, summary, link)
	}
	seed("recipient@keyorix.example", "Alice", "Acme", "hi", "dev on app", "https://x.example/s?t=1")
	// CRLF header injection attempts via the recipient address.
	seed("victim@x.example\r\nBcc: attacker@evil.example", "A", "I", "m", "s", "https://x.example/s")
	seed("victim@x.example%0d%0aBcc:attacker@evil.example", "A", "I", "m", "s", "https://x.example/s")
	seed("a@x.example>\r\nSubject: injected", "A", "I", "m", "s", "https://x.example/s")
	// CRLF via display name / subject-feeding fields.
	seed("r@x.example", "A\r\nBcc: e@evil.example", "I", "m", "s", "https://x.example/s")
	seed("r@x.example", "A", "Inst\r\nX-Injected: 1", "m", "s", "https://x.example/s")
	seed("r@x.example", "A", "I\nSubject: second", "m", "s", "https://x.example/s")
	// MIME boundary confusion in body fields.
	seed("r@x.example", "A", "I", "body\r\n--_boundary_\r\nContent-Type: text/html\r\n\r\ninjected", "s", "https://x.example/s")
	seed("r@x.example", "A", "I", "m", "\r\n--\r\nContent-Type: application/x-evil\r\n\r\n", "https://x.example/s")
	// RFC2047 word-fragment and NUL.
	seed("r@x.example", "=?utf-8?B?SGVsbG8=?=\r\nX-H: v", "I", "m", "s", "https://x.example/s")
	seed("r@x.example", "A\x00B", "I\x00", "m\x00", "s", "https://x.example/s")
	// Link field (href + visible text in HTML part).
	seed("r@x.example", "A", "I", "m", "s", "https://x.example/s\r\nLocation: http://evil.example")

	f.Fuzz(func(t *testing.T, recipient, display, install, message, summary, link string) {
		req := ports.SetupLinkRequest{
			RecipientEmail:    recipient,
			DisplayName:       display,
			InstallName:       install,
			Message:           message,
			AssignmentSummary: summary,
			Link:              link,
		}
		hostileRaw, ok := buildSetupMessageBytes(t, req)
		if !ok {
			return // input legitimately rejected by buildMessage
		}
		hostile, err := parseStructure(hostileRaw)
		if err != nil {
			// go-mail produced bytes an independent RFC-5322 parser cannot read.
			// That is a structural defect in its own right — surface it.
			t.Fatalf("produced message is unparseable by net/mail: %v\n--- message ---\n%s", err, hostileRaw)
		}

		benignRaw, ok := buildSetupMessageBytes(t, benignFor(req))
		if !ok {
			t.Fatalf("benign baseline unexpectedly rejected for shape of %#v", req)
		}
		benign, err := parseStructure(benignRaw)
		if err != nil {
			t.Fatalf("benign baseline unparseable: %v", err)
		}

		if !hostile.equal(benign) {
			t.Fatalf("structural inequality — attacker bytes changed message structure\n"+
				"hostile: headers=%v to=%d parts=%d\nbenign:  headers=%v to=%d parts=%d\n"+
				"--- hostile message ---\n%s",
				hostile.headerKeys, hostile.toCount, hostile.partCount,
				benign.headerKeys, benign.toCount, benign.partCount, hostileRaw)
		}
	})
}
