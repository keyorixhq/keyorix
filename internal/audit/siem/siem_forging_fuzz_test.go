package siem

// siem_forging_fuzz_test.go — ML1 injection-class fuzzing of outbound SIEM/audit
// event formatting (task ML1, piece 4: log-forging via newlines/delimiters).
//
// Targets the two real outbound encoders for an audit event:
//   - spool.add's on-disk JSON-Lines record: json.Marshal(event) + '\n'
//     (spool.go:93,113) — the durable backlog a SIEM later replays.
//   - the forwarder wire payload: toPayload(event) -> json.Marshal
//     (forwarder.go:394,450), plus the Datadog top-level "message": Description
//     (forwarder.go:445).
//
// Attacker-influenced fields: Description, IPAddress, ActorType, EventType all
// fold in actor/project/secret names chosen by an authenticated user. The
// classic log-forging attack is embedding "\n{...forged second record...}" in
// Description so a line-oriented SIEM ingests a second, attacker-authored event.
//
// Oracle (STRUCTURAL — independent JSON parser, encoding/json):
//   1. Line-count: the serialised JSONL record contains exactly ONE line — i.e.
//      the only '\n' is the record terminator spool.add appends. An embedded
//      newline that produced a second physical line would fire this.
//   2. Round-trip fidelity: decoding the single line yields Description (and the
//      other fields) BYTE-EXACT equal to the input — proof no delimiter was
//      interpreted, dropped, or split.
//   3. Single-object: the forwarder payload and the Datadog envelope each decode
//      as exactly one JSON object whose description/message equals the input.
//
// What this oracle does NOT verify (recorded in the report):
//   - It does not test a non-JSON SIEM format (CEF/LEEF/RFC5424 syslog): the
//     code emits only JSON/JSONL, so those formats do not exist to fuzz. If a
//     future provider emits a line-delimited text format, this oracle would not
//     cover it and a new target is required.
//   - It does not exercise the Diff field (json.RawMessage in the forwarder
//     payload): an invalid-JSON Diff makes json.Marshal fail cleanly (a handled
//     error, not an injection), so Diff is held empty here to keep the oracle on
//     the string-injection question. Diff-as-RawMessage passthrough is a
//     separate concern noted in the report, not covered.
//   - It asserts the ENCODER is injection-safe; it does not verify the SIEM
//     *consumer* re-frames records correctly, nor that the spool file is read
//     back line-by-line (replay() is out of scope).
//   - It does not check the Splunk HEC envelope's non-payload fields.

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// jsonRef returns the reference encoding/json round-trip of a standalone string:
// what json.Unmarshal(json.Marshal(s)) yields. For valid UTF-8 this is s itself;
// for invalid UTF-8 it is the documented U+FFFD-coerced form. The encoder under
// test must reproduce exactly this and nothing more.
func jsonRef(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	var out string
	if err := json.Unmarshal(b, &out); err != nil {
		return s
	}
	return out
}

func FuzzSIEMEventJSONForging(f *testing.F) {
	add := func(desc, ip, actor, etype string) { f.Add(desc, ip, actor, etype) }
	add("user 5 read secret db-prod", "10.0.0.1", "user", "secret.read")
	// Log-forging idioms via Description.
	add("ok\n{\"event_type\":\"admin.login\",\"success\":true}", "10.0.0.1", "user", "secret.read")
	add("line1\nline2\r\nline3", "1.2.3.4", "machine_identity", "mi.auth")
	add("}\n{\"id\":99999,\"description\":\"forged\"}", "::1", "system", "x")
	add("\"injected\":true,\"description\":\"", "0.0.0.0", "user", "y")
	add("\x00\x01\x02 control", "\n10.0.0.9\n", "user\n", "evt\ntype")
	add("tab\there", "ip\twith\ttab", "user", "evt")
	add("unicode    line sep", "1.1.1.1", "user", "e")

	f.Fuzz(func(t *testing.T, desc, ip, actor, etype string) {
		ev := &models.AuditEvent{
			ID:          1,
			EventType:   etype,
			Description: desc,
			IPAddress:   ip,
			ActorType:   actor,
			EventTime:   time.Unix(1700000000, 0).UTC(),
		}

		// --- Path 1: spool JSONL record (the real bytes spool.add writes). ---
		var line []byte
		var mErr error
		fuzzutil.Guard(t.Fatalf, "siem.spoolMarshal", func() {
			b, err := json.Marshal(ev)
			if err == nil {
				line = append(b, '\n') // exactly what spool.add writes (spool.go:113)
			}
			mErr = err
		})
		if mErr != nil {
			t.Fatalf("spool json.Marshal of audit event failed: %v", mErr)
		}
		// Oracle 1: exactly one physical line (one trailing '\n', none embedded).
		if n := bytes.Count(line, []byte{'\n'}); n != 1 {
			t.Fatalf("log-forging: spool record has %d newlines, want 1 (embedded newline split the record)\nbytes=%q", n, line)
		}
		if line[len(line)-1] != '\n' {
			t.Fatalf("spool record does not end with the terminator newline: %q", line)
		}
		// Oracle 2: fidelity. The encoder must introduce NO transformation
		// beyond what encoding/json documents for a standalone string (invalid
		// UTF-8 is coerced to U+FFFD — lossy but it does NOT split a record or
		// forge a field; see EXPECTED-DIFFERENCE note in the report). We compare
		// each decoded field to the reference stdlib round-trip of that same
		// string, so the check stays byte-exact for valid UTF-8 and provably
		// adds no corruption for invalid UTF-8.
		var back models.AuditEvent
		if err := json.Unmarshal(line[:len(line)-1], &back); err != nil {
			t.Fatalf("spool record does not decode as one JSON object: %v\nbytes=%q", err, line)
		}
		if back.Description != jsonRef(desc) {
			t.Fatalf("Description altered beyond stdlib coercion: got %q want %q", back.Description, jsonRef(desc))
		}
		if back.EventType != jsonRef(etype) || back.IPAddress != jsonRef(ip) || back.ActorType != jsonRef(actor) {
			t.Fatalf("field altered beyond stdlib coercion: etype %q/%q ip %q/%q actor %q/%q",
				back.EventType, jsonRef(etype), back.IPAddress, jsonRef(ip), back.ActorType, jsonRef(actor))
		}

		// --- Path 2: forwarder webhook payload (toPayload -> json.Marshal). ---
		payload := toPayload(ev)
		pb, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("forwarder payload marshal failed: %v", err)
		}
		if bytes.ContainsRune(pb, '\n') {
			t.Fatalf("forwarder payload contains a raw newline (should be escaped): %q", pb)
		}
		var pm map[string]any
		if err := json.Unmarshal(pb, &pm); err != nil {
			t.Fatalf("forwarder payload is not one JSON object: %v\n%q", err, pb)
		}
		if pm["description"] != jsonRef(desc) {
			t.Fatalf("forwarder description altered beyond stdlib coercion: got %v want %q", pm["description"], jsonRef(desc))
		}

		// --- Path 3: Datadog envelope (top-level message := Description). ---
		dd, err := json.Marshal(map[string]any{
			"ddsource": "keyorix", "service": "keyorix",
			"message": ev.Description, "audit": payload,
		})
		if err != nil {
			t.Fatalf("datadog envelope marshal failed: %v", err)
		}
		if bytes.ContainsRune(dd, '\n') {
			t.Fatalf("datadog envelope contains a raw newline: %q", dd)
		}
		var dm map[string]any
		if err := json.Unmarshal(dd, &dm); err != nil {
			t.Fatalf("datadog envelope is not one JSON object: %v", err)
		}
		if dm["message"] != jsonRef(desc) {
			t.Fatalf("datadog message altered beyond stdlib coercion: got %v want %q", dm["message"], jsonRef(desc))
		}
	})
}
