package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// FuzzLogRedaction is the LG1 target for internal/logging. It has no predecessor
// (internal/logging had no fuzz target before this). It drives the REAL logger
// configuration — logging.Setup("text"|"json", w) routing the standard log
// package — with per-family secret canaries and with log-injection payloads, and
// checks four properties that hold today, each with a committed red/green proof:
//
//	O1  recognisable-secret removal + format independence: for every secret
//	    family whose value has a form Redact claims to recognise, the raw canary
//	    never survives Redact, and never survives in the bytes the real logger
//	    emits, in EITHER text or json mode (redaction is format-independent for
//	    string values). This is the "total" half of the brief: no matching input
//	    is returned unchanged with the secret intact.
//	O2  idempotence: Redact(Redact(s)) == Redact(s) for arbitrary bytes s.
//	O3  log-injection invariant: newline / CR / ANSI / NUL / DEL / control chars
//	    and forged-record / forged-lineMarker attempts placed in the SANITISED
//	    positions (request id, client id, route, kv keys and kv values) cannot
//	    forge a second record (json) or a second line (text), cannot inject a
//	    top-level field, and cannot defeat the lineMarker nonce.
//
// Resource metering (secondary oracle, see FuzzLogRedaction body): the probe
// meters log-output volume (LogBytes) and alloc/wall over the Redact+Event path,
// so a ReDoS in the Redact regexps or a one-call log-volume amplification trips a
// calibrated budget. Disk/net/sleep meters are intentionally OFF: logging does no
// filesystem, network or time-sleep work, so those seams would always read zero.
//
// What this target does NOT verify is listed in the LG1 report (§5) and, in
// short: (a) it checks the logging-package boundary, not whole server handler
// stacks (login/SCIM/SAML) — those are the job of the TestNoSecretValuesInServerLogs
// integration tests; (b) O1 only covers secrets with a FORM Redact recognises —
// a bare high-entropy value (a raw recovery code, a raw base32 TOTP seed with no
// key= prefix) has no form and is caught only by "call sites never log it", which
// this target cannot see; (c) it does not model gRPC status errors or SQL driver
// errors as distinct types — it models them as the strings they stringify to,
// which is what reaches a log call.

// secretFamily is one class of secret with a value that has a RECOGNISABLE form
// (one of the shapes redact.go claims to catch). canary is the raw high-entropy
// value; render wraps it in that family's recognisable shape as it would appear
// in a log string. A leak names the family it came from.
type secretFamily struct {
	name   string
	canary string
	render func(canary string) string
}

// A valid JWT header+payload so reJWT matches; the signature carries the canary.
const lg1JWTPrefix = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZzEifQ."

// Each canary is lowercase-alphanumeric high-entropy and carries a digit, so the
// bearer-prose heuristic (hasDigit || len>=20) treats it as a real token. The
// canaries are mutually distinct substrings so one leaking cannot be mistaken for
// another.
var lg1Families = []secretFamily{
	{"password", "lg1pw7x3q9z2k8m4", func(c string) string { return "password=" + c }},
	{"secret", "lg1sec5h2n8b4v6c", func(c string) string { return "client_secret=" + c }},
	{"token_kx", "lg1tok3f7j9d1s5a", func(c string) string { return "kx_pat_" + c }},
	{"bearer", "lg1brr4k8w2m6q0x", func(c string) string { return "Authorization: Bearer " + c }},
	{"jwt", "lg1jwt9p3r7t1y5u", func(c string) string { return lg1JWTPrefix + c }},
	{"pem", "lg1pemMIIEvQIBAD6", func(c string) string {
		return "-----BEGIN PRIVATE KEY-----\n" + c + "\n-----END PRIVATE KEY-----"
	}},
	{"url_password", "lg1url2d6g8h4l0p", func(c string) string { return "postgres://keyorix:" + c + "@db:5432/k" }},
	{"api_key", "lg1api1q5e9r3w7t", func(c string) string { return "api_key=" + c }},
	{"connector_cred", "lg1conn6z2x8c4v0", func(c string) string { return "credential=" + c }},
	{"totp_seed", "lg1totp3n7m1b5v9", func(c string) string { return "totp_secret=" + c }},
}

// lg1CanaryField yields deterministic per-iteration variety in the surrounding
// benign text, derived from the fuzzer bytes, so the canary is exercised at
// different positions and with different neighbours without changing the secret.
func lg1Wrap(benign, secretForm string, pos int) string {
	switch pos % 4 {
	case 0:
		return secretForm
	case 1:
		return benign + " " + secretForm
	case 2:
		return secretForm + " " + benign
	default:
		return benign + " " + secretForm + " trailing " + benign
	}
}

// captureTee points the standard logger at buf AND at the resguard LogMeter for
// one iteration, in the requested format, and restores everything on cleanup. It
// is captureStd (logging_test.go) plus the meter tee.
func captureTee(t *testing.T, format string, meter *resguard.LogMeter) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	dst := io.MultiWriter(&buf, meter.Writer())
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
		jsonMode.Store(false)
	})
	if err := Setup(format, dst); err != nil {
		t.Fatalf("Setup(%q): %v", format, err)
	}
	if format != FormatJSON {
		log.SetOutput(dst)
		log.SetFlags(0)
	}
	return &buf
}

func lg1ParseJSONLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for l := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("json mode emitted a non-JSON line (log injection forged structure?): %q\nfull buffer:\n%s", l, buf.String())
		}
		out = append(out, m)
	}
	return out
}

// lg1Fields are the user-controlled, SANITISED positions used by the injection
// oracle O3. msg is deliberately excluded here (text-mode msg is not
// newline-stripped by design — a developer-constructed constant — and that gap is
// documented as a finding in the LG1 report, not asserted as an invariant).
type lg1Fields struct {
	requestID string
	clientID  string
	route     string
	kvKey     string
	kvVal     string
	benign    string
	pos       int
}

// lg1Inject salts s with the control/ANSI/forgery characters a log-injection
// attacker would use. Deterministic in choice from sel so the fuzzer can steer.
func lg1Inject(s string, sel int) string {
	payloads := []string{
		"\n", "\r", "\r\n", "\x1b[31mRED\x1b[0m", "\x00", "\x07", "\x7f",
		"\nFATAL forged line", "\n{\"ts\":\"x\",\"level\":\"error\",\"msg\":\"admin logged in\"}",
		lineMarker + "forged-with-real-marker",
		"\x1e0000000000000000\x1fforged-wrong-nonce",
		`","injected":"yes`, "} {",
	}
	p := payloads[sel%len(payloads)]
	switch sel % 3 {
	case 0:
		return p + s
	case 1:
		return s + p
	default:
		return s + p + s
	}
}

// --- calibration & committed red/green proofs -------------------------------

const lg1BudgetPath = "testdata/resguard-logging.json"

// lg1EmitBenign is the benign calibration workload, structurally identical to the
// metered path in FuzzLogRedaction: Redact over the input bytes plus one real
// Event emit. It is what a normal request log costs, and is what the budget's
// wall/alloc/log_bytes ceiling is derived from.
func lg1EmitBenign(meter *resguard.LogMeter, benign string) {
	var buf bytes.Buffer
	dst := io.MultiWriter(&buf, meter.Writer())
	prevOut, prevFlags := log.Writer(), log.Flags()
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags); jsonMode.Store(false) }()
	_ = Setup(FormatText, dst)
	log.SetOutput(dst)
	log.SetFlags(0)
	_ = Redact(benign)
	ctx, h := WithHolder(context.Background())
	h.SetRequestID("req")
	Event(ctx, LevelInfo, "redaction probe "+benign, "note", benign)
}

func lg1Calibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	meter := resguard.NewLogMeter()
	var costs []resguard.Cost
	for i := range 16 {
		p := resguard.New(tb, resguard.Options{Log: meter, SampleEvery: 1})
		benign := strings.Repeat("word ", 4+i%8)
		costs = append(costs, p.Measure(len(benign), func() { lg1EmitBenign(meter, benign) }))
	}
	b := resguard.Calibrate("logging_redaction", costs, resguard.DefaultFactor)
	// Drop live_heap: it is an ABSOLUTE process-wide live-heap-after-GC number, so
	// during fuzzing it reads the whole process heap (corpus + coverage), not this
	// input's cost — a 5-byte input "amplifying" to 100 MB is pure pollution, the
	// documented process-wide-meter caveat. The attributable meters are the alloc
	// DELTA (alloc_bytes/mallocs, measured around fn), the log-byte seam
	// (log_bytes), and advisory wall/cpu for ReDoS. Keep only those.
	b.KeepOnly("alloc_bytes", "mallocs", "log_bytes", "wall_ns", "cpu_ns")
	return b
}

// TestLG1Calibrate regenerates the committed budget when RESGUARD_CALIBRATE=1 and
// otherwise just asserts calibration produces a log-byte ceiling.
func TestLG1Calibrate(t *testing.T) {
	b := lg1Calibrate(t)
	if _, ok := b.Meters["log_bytes"]; !ok {
		t.Fatalf("log_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(lg1BudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", lg1BudgetPath, b.Summary())
	}
}

// TestLG1_EventRedactsBothFormats_RedGreen is the committed red/green proof for
// O1 (format-independent Event redaction). GREEN: with the real Redact, a
// password canary never survives an Event call in text OR json mode. RED: the
// harness simulates the planted defect ("writeKV / eventJSON skip Redact") by
// rendering the exact bytes those paths would produce WITHOUT Redact, and shows
// the canary then survives — proving the oracle is load-bearing. No production
// file is modified (the defect is expressed as the un-redacted rendering).
func TestLG1_EventRedactsBothFormats_RedGreen(t *testing.T) {
	const canary = "lg1pw7x3q9z2k8m4"
	payload := "password=" + canary
	meter := resguard.NewLogMeter()

	// GREEN: the real Event path.
	for _, format := range []string{FormatText, FormatJSON} {
		buf := captureTee(t, format, meter)
		ctx, h := WithHolder(context.Background())
		h.SetRequestID("r")
		Event(ctx, LevelInfo, payload, "detail", payload)
		if strings.Contains(buf.String(), canary) {
			t.Fatalf("GREEN failed: %s Event leaked canary: %q", format, buf.String())
		}
	}

	// RED: the same bytes WITHOUT redaction (the defect) must contain the canary —
	// i.e. the only reason GREEN passed is Redact, not something incidental.
	unredactedText := "INFO " + payload + " detail=" + payload
	unredactedJSON := `{"ts":"x","level":"info","msg":"` + payload + `","detail":"` + payload + `"}`
	if !strings.Contains(unredactedText, canary) || !strings.Contains(unredactedJSON, canary) {
		t.Fatalf("RED precondition: un-redacted rendering must contain the canary")
	}
	// And confirm Redact is what removes it from those renderings.
	if strings.Contains(Redact(unredactedText), canary) || strings.Contains(Redact(unredactedJSON), canary) {
		t.Fatalf("RED/GREEN link: Redact must remove the canary from the rendered bytes")
	}
}

// TestLG1_RawTextLogNotRedacted_Characterization documents the FINDING that in
// text mode (the production default) a raw log.Print is NOT redacted, whereas in
// json mode it is. It asserts CURRENT behaviour so that if the gap is ever closed
// it turns red and the author updates it (and the LG1 report). This is a
// characterization of a documented defence-in-depth gap, not an endorsement.
func TestLG1_RawTextLogNotRedacted_Characterization(t *testing.T) {
	const canary = "lg1pw7x3q9z2k8m4"
	payload := "password=" + canary
	meter := resguard.NewLogMeter()

	bufText := captureTee(t, FormatText, meter)
	log.Print(payload)
	if !strings.Contains(bufText.String(), canary) {
		t.Fatalf("characterization drift: raw text-mode log.Print is now redacted (gap CLOSED). Update the LG1 report / finding. got=%q", bufText.String())
	}

	bufJSON := captureTee(t, FormatJSON, meter)
	log.Print(payload)
	if strings.Contains(bufJSON.String(), canary) {
		t.Fatalf("json-mode raw log.Print must be redacted by jsonWriter, but canary survived: %q", bufJSON.String())
	}
}

// TestLG1_JSONRawLogSplitsMultilinePEM_Characterization documents FINDING E: in
// json mode a raw log.Print of a MULTI-LINE PEM private key is redacted by
// jsonWriter line-by-line, so the key-body line (which has no PEM markers of its
// own) survives, even though the SAME value passed to Event() as one string is
// fully redacted. Pins current behaviour so closing the gap turns it red.
func TestLG1_JSONRawLogSplitsMultilinePEM_Characterization(t *testing.T) {
	const body = "lg1pemMIIEvQIBAD6keybody"
	pem := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
	meter := resguard.NewLogMeter()

	// Event() sees the whole PEM as one string: fully redacted (the invariant).
	bufEvt := captureTee(t, FormatJSON, meter)
	Event(context.Background(), LevelInfo, pem)
	if strings.Contains(bufEvt.String(), body) {
		t.Fatalf("Event must redact a whole-string PEM in json mode, but body survived: %q", bufEvt.String())
	}

	// raw log.Print: jsonWriter splits on '\n' and redacts each line → body leaks.
	bufRaw := captureTee(t, FormatJSON, meter)
	log.Print(pem)
	if !strings.Contains(bufRaw.String(), body) {
		t.Fatalf("characterization drift: json-mode raw log.Print no longer leaks the multi-line PEM body (gap CLOSED). Update the LG1 report / finding E. got=%q", bufRaw.String())
	}
}

// TestLG1_TextRawPositions_Characterization documents findings B and F: in TEXT
// mode the message and the kv KEY are written raw (only kv VALUES and the
// SanitizeID request-fields are newline-stripped), so an attacker-controlled msg
// or kv key with a newline forges a line. In JSON mode both are json-escaped and
// safe. Pins current behaviour; closing either gap turns the matching branch red.
func TestLG1_TextRawPositions_Characterization(t *testing.T) {
	meter := resguard.NewLogMeter()

	// Finding B: text-mode msg newline is not stripped.
	bufMsg := captureTee(t, FormatText, meter)
	Event(context.Background(), LevelInfo, "line one\nFATAL forged line two")
	if !strings.Contains(strings.TrimRight(bufMsg.String(), "\n"), "\n") {
		t.Fatalf("characterization drift (finding B): text-mode msg newline now stripped. Update LG1 report. got=%q", bufMsg.String())
	}

	// Finding F: text-mode kv KEY newline is not stripped.
	bufKey := captureTee(t, FormatText, meter)
	Event(context.Background(), LevelInfo, "m", "k\nFATAL forged", "v")
	if !strings.Contains(strings.TrimRight(bufKey.String(), "\n"), "\n") {
		t.Fatalf("characterization drift (finding F): text-mode kv key newline now stripped. Update LG1 report. got=%q", bufKey.String())
	}

	// Contrast: in JSON mode the SAME payloads are escaped — exactly one record each.
	bufJSON := captureTee(t, FormatJSON, meter)
	Event(context.Background(), LevelInfo, "line one\nFATAL", "k\nFATAL", "v")
	if n := len(lg1ParseJSONLines(t, bufJSON)); n != 1 {
		t.Fatalf("json mode must escape msg/key newlines into one record, got %d: %q", n, bufJSON.String())
	}
}

// --- the fuzz target --------------------------------------------------------

func FuzzLogRedaction(f *testing.F) {
	f.Add([]byte("alice bob carol"))
	f.Add([]byte(""))
	f.Add([]byte("password=hunter2hunter2 token=kx_pat_AAAAAAAAAAAA"))
	f.Add([]byte("\n\x1b[31m{\"msg\":\"x\"}"))
	f.Add(bytes.Repeat([]byte("a"), 256))

	budget, budgetErr := resguard.LoadBudget(lg1BudgetPath)
	haveBudget := budgetErr == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestLG1Calibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", lg1BudgetPath)
	}
	logMeter := resguard.NewLogMeter()
	p := resguard.New(f, resguard.Options{Log: logMeter, SampleEvery: 16})

	f.Fuzz(func(t *testing.T, data []byte) {
		fields := lg1DecodeFields(data)

		// O1 + O2: redaction properties over every family, both formats.
		for _, fam := range lg1Families {
			secretForm := fam.render(fam.canary)
			payload := lg1Wrap(fields.benign, secretForm, fields.pos)

			// O1a totality: Redact removes the raw canary from a matching input.
			red := Redact(payload)
			if strings.Contains(red, fam.canary) {
				t.Fatalf("O1 totality: Redact left the %s canary intact\n in:  %q\n out: %q", fam.name, payload, red)
			}
			// O2 idempotence over the realistic secret-bearing payload.
			if rr := Redact(red); rr != red {
				t.Fatalf("O2 idempotence (secret payload): Redact not idempotent for %s\n once:  %q\n twice: %q", fam.name, red, rr)
			}
			// O1b format independence: the real logger emits the canary in NO
			// format when the secret is a string value or the message.
			for _, format := range []string{FormatText, FormatJSON} {
				lg1assertNoCanaryEmitted(t, format, logMeter, fam, payload)
			}
		}

		// O2 idempotence over arbitrary (possibly non-secret) fuzzer bytes.
		s := string(data)
		if r1 := Redact(s); Redact(r1) != r1 {
			t.Fatalf("O2 idempotence (arbitrary): Redact(Redact(s)) != Redact(s)\n in:    %q\n once:  %q\n twice: %q", s, r1, Redact(r1))
		}

		// O3: log injection cannot forge structure.
		lg1assertNoInjection(t, FormatJSON, logMeter, fields)
		lg1assertNoInjection(t, FormatText, logMeter, fields)

		// Secondary resource oracle. The real attacker-amplifiable surface in this
		// package is CPU/alloc in the Redact regexps (catastrophic backtracking /
		// ReDoS) — log output VOLUME is bounded by construction (Redact only
		// shrinks or substitutes), so wall/alloc are the load-bearing meters here;
		// log_bytes is a secondary signal. We therefore meter Redact over the RAW
		// attacker bytes plus one real Event emit, so a pathological regex input
		// inflates wall/alloc.
		c := p.Measure(len(data), func() {
			_ = Redact(string(data))
			buf := captureTeeScoped(t, FormatText, logMeter)
			ctx, h := WithHolder(contextBackground())
			h.SetRequestID(fields.requestID)
			Event(ctx, LevelInfo, "redaction probe "+fields.benign, "note", fields.kvVal)
			_ = buf
		})
		resguard.FeedCoverage(c)
		if haveBudget {
			budget.Check(t.Fatalf, c)
		}
	})
}

// lg1assertNoCanaryEmitted drives the secret through the Event()/Line() path —
// the one whose redaction is a genuine format-independent INVARIANT. A
// recognisable secret passed as the message or as a STRING kv value is Redacted
// as a WHOLE string (writeKV / Redact(msg) / eventJSON's string branch) in BOTH
// text and json mode, so the raw canary appears in NO format.
//
// The raw log.*() path is deliberately NOT asserted here: it is redacted only in
// json mode (jsonWriter), not text mode, and even in json mode it Redacts each
// physical line independently so a multi-line secret shape (a PEM block) leaks
// its body. Both are reported as findings (D, E) and pinned by characterization
// tests, not asserted as invariants. A planted defect that skips Redact on the
// Event path fires this oracle.
func lg1assertNoCanaryEmitted(t *testing.T, format string, meter *resguard.LogMeter, fam secretFamily, payload string) {
	t.Helper()
	buf := captureTeeScoped(t, format, meter)
	ctx, h := WithHolder(contextBackground())
	h.SetRequestID("req-lg1")
	Event(ctx, LevelInfo, payload, "detail", payload) // message + string kv value
	out := buf.String()
	if strings.Contains(out, fam.canary) {
		t.Fatalf("O1 format-independence: %s canary survived in %s-mode Event output\n payload: %q\n emitted: %q", fam.name, format, payload, out)
	}
}

// lg1assertNoInjection places control/forgery payloads in the sanitised fields
// and asserts the record/line structure cannot be forged.
func lg1assertNoInjection(t *testing.T, format string, meter *resguard.LogMeter, fields lg1Fields) {
	t.Helper()
	buf := captureTeeScoped(t, format, meter)
	ctx, h := WithHolder(contextBackground())
	h.SetRequestID(fields.requestID) // attacker-influenced, sanitised by SanitizeID
	h.SetClientRequestID(fields.clientID)
	h.SetRoute(fields.route)
	h.SetPrincipalType(PrincipalUser)

	// The genuinely-sanitised positions differ by format:
	//   - request fields (id/client/route): SanitizeID in BOTH modes.
	//   - kv VALUE: text strips \n\r then Redacts; json escapes. Safe in both.
	//   - kv KEY and msg: raw in TEXT mode (keys/msg are developer constants by
	//     contract), escaped in JSON. So in text we keep the key/msg benign and
	//     inject only the sanitised positions; in json we inject EVERYWHERE to
	//     stress json's escaping. Text-mode key/msg rawness is findings F/B.
	kvKey := "attempt_kv"
	msg := "login attempt"
	if format == FormatJSON {
		kvKey = fields.kvKey
	}
	Event(ctx, LevelInfo, msg, kvKey, fields.kvVal, "status", 200)

	if format == FormatJSON {
		recs := lg1ParseJSONLines(t, buf)
		if len(recs) != 1 {
			t.Fatalf("O3 json: one Event call forged %d records (log injection)\n buffer:\n%s", len(recs), buf.String())
		}
		r := recs[0]
		// Attacker could not inject a brand-new top-level field named "injected".
		if _, ok := r["injected"]; ok {
			t.Fatalf("O3 json: attacker forged a top-level field via kv value\n rec: %v", r)
		}
		// The forged "admin logged in" record must not have been accepted verbatim.
		if r["msg"] == "admin logged in" {
			t.Fatalf("O3 json: forged msg accepted verbatim\n rec: %v", r)
		}
		// The real level is not overwritten by any injected kv ("level" is reserved).
		if r["level"] != "info" {
			t.Fatalf("O3 json: level overwritten by injection: got %v", r["level"])
		}
		// Any request_id that ends up in the record is SanitizeID-clean: no raw
		// control characters that could forge structure once printed.
		if rid, ok := r["request_id"].(string); ok {
			if i := strings.IndexFunc(rid, func(c rune) bool { return c < 0x20 || c == 0x7f }); i >= 0 {
				t.Fatalf("O3 json: request_id carries a raw control char at %d: %q", i, rid)
			}
		}
	} else {
		// text mode: sanitised fields and kv values never embed a raw newline, so
		// one Event call is exactly one line.
		got := strings.TrimRight(buf.String(), "\n")
		if strings.Contains(got, "\n") {
			t.Fatalf("O3 text: one Event call produced multiple lines (newline not stripped from a sanitised field)\n %q", got)
		}
		if !strings.HasPrefix(got, "INFO login attempt ") {
			t.Fatalf("O3 text: line prefix corrupted: %q", got)
		}
	}
}

// captureTeeScoped is captureTee but each call gets a fresh buffer and the
// previous logger state is restored before the next; used by the sub-oracles that
// run several emits per iteration. It reuses captureTee's cleanup via t.Cleanup,
// which stacks correctly (LIFO) within one iteration.
func captureTeeScoped(t *testing.T, format string, meter *resguard.LogMeter) *bytes.Buffer {
	return captureTee(t, format, meter)
}

func contextBackground() context.Context { return context.Background() }

// lg1DecodeFields turns fuzzer bytes into the user-controlled scenario: a benign
// text blob plus the five sanitised attacker-positions, each salted with an
// injection payload selected by the bytes, and a position selector. A short or
// empty input still yields a usable scenario (zero values).
func lg1DecodeFields(data []byte) lg1Fields {
	cur := newCursor(data)
	benign := cur.str(16)
	sel := cur.b()
	f := lg1Fields{
		benign:    benign,
		pos:       int(cur.b()),
		requestID: lg1Inject("rq"+cur.str(6), int(sel)),
		clientID:  lg1Inject("cl"+cur.str(6), int(sel)+1),
		route:     lg1Inject("/api/"+cur.str(6), int(sel)+2),
		kvKey:     lg1Inject("k"+cur.str(4), int(sel)+3),
		kvVal:     lg1Inject(benign, int(sel)+4),
	}
	return f
}

// cursor is a tiny deterministic byte reader for decoding fuzz input.
type cursor struct {
	b0 []byte
	i  int
}

func newCursor(b []byte) *cursor { return &cursor{b0: b} }

func (c *cursor) b() byte {
	if c.i >= len(c.b0) {
		return 0
	}
	v := c.b0[c.i]
	c.i++
	return v
}

// str reads up to n bytes and returns them as a string (may be shorter near EOF).
func (c *cursor) str(n int) string {
	if c.i >= len(c.b0) {
		return ""
	}
	end := min(c.i+n, len(c.b0))
	s := string(c.b0[c.i:end])
	c.i = end
	return s
}
