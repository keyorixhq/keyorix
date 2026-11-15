// hardened_response_fuzz_test.go — GP1 hostile-response fuzzing of the shared
// hardened outbound HTTP-client response layer (hardened_client.go) that every
// Connect cloud backend (Azure Key Vault, Vault, AWS Secrets Manager) routes its
// responses through. The task names this layer explicitly ("include the HTTP
// client layer if it parses redirects, content-length or content-type").
//
// These four targets are PURE-FUNCTION / in-memory: no network, no httptest
// servers, no SDK — so they run fast and measure bounded work per input size
// directly, complementing the server-driven FuzzAzureKVHostileEndpoint /
// FuzzAWSSMHostileEndpoint / FuzzK8sTokenRequestHostileAPI targets rather than
// repeating them.
//
// Every oracle is a NAMED self-consistency law or a differential against an
// INDEPENDENT reference (a regexp engine, a counting model, a re-derivation on the
// drained prefix), never "does not panic" alone. What each oracle does NOT verify is stated in its
// doc comment and in /mnt/data/wave4/out/gp1-REPORT.md.
//
// Reachability (live callers, no production change):
//   - scrubbedErrorBody / validErrorCode / errorBodyScrubRoundTripper: installed
//     by newAzureHardenedTransport (hardened_client.go) which azurekv.go wires as
//     the Azure Key Vault connector's transport (azurekv.go client()).
//   - cappedBodyReader: installed by sizeCappedRoundTripper inside
//     newConnectHardenedTransport, used by every backend's hardened transport.

package connect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
)

// ----------------------------------------------------------------------------
// Independent references (written from the documented contract, NOT copied from
// hardened_client.go).
// ----------------------------------------------------------------------------

// refErrorCodeRe is the error-code charset+length contract, restated as a
// regexp so the reference uses a genuinely different engine than validErrorCode's
// hand-rolled byte loop. Contract (hardened_client.go doc): a plain top-level
// error.code of [A-Za-z0-9_.-], 1..64 bytes.
var refErrorCodeRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// refExtractErrorCode is a reference extractor of the top-level string-typed
// error.code a hostile body carries. It uses pointer fields so "code absent" and
// "code present but null/non-string" are distinguished from "code: \"\"".
//
// Shared-decoder caveat (honest, and the reason the FIRST map-walk attempt was a
// harness bug): the top-level error.code the contract refers to is DEFINED by
// encoding/json's decode rules — which match struct tags CASE-INSENSITIVELY and
// resolve \uXXXX escapes and duplicate keys last-wins. An earlier version walked a
// map[string]json.RawMessage with case-SENSITIVE key lookups and so disagreed with
// production on a hostile {"error":{"Code":...}} — a reference bug, not a Keyorix
// defect (the extracted code is still charset-bounded by L3). This reference
// therefore decodes with encoding/json too, so a pure json quirk is shared and the
// L4 differential cannot catch it; L1/L2/L3/L5 are the laws that hold independently
// of the decoder, and L4 still catches any bug in the validErrorCode gating, the
// UpstreamError fallback, or a mangled/truncated/wrong-field value (e.g. Plant D).
func refExtractErrorCode(original []byte) (code string, present bool) {
	var d struct {
		Error *struct {
			Code *string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(original, &d) != nil || d.Error == nil || d.Error.Code == nil {
		return "", false
	}
	return *d.Error.Code, true
}

// scrubbedShape is the exact structure scrubbedErrorBody must always emit.
type scrubbedShape struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

const scrubMessage = "upstream error response body suppressed"

// assertScrubbedBodyLaws checks the laws every scrubbedErrorBody output must
// satisfy, against the original input. Returns the emitted code for callers that
// want to assert more. These laws are the oracle O-SCRUB:
//
//	L1  the output is valid JSON (an SDK/json parser must be able to read it);
//	L2  it re-decodes to EXACTLY {"error":{"code":<str>,"message":<const>}} with
//	    no unknown fields, and message is the fixed suppression string;
//	L3  code matches the independent charset/length regexp — so NO attacker byte
//	    outside [A-Za-z0-9_.-] can ride out in the code (quote/backslash/control/
//	    newline injection into the body the SDK then parses);
//	L4  differential: if the independent extractor found a charset-clean code,
//	    the output MUST echo exactly that; otherwise it MUST collapse to the fixed
//	    "UpstreamError" sentinel (no invented or partial code);
//	L5  bounded output: length <= template + 64, independent of |original|.
//
// Does NOT verify: that the SDK downstream actually parses the scrubbed body to
// a sensible ResponseError (that is the SDK's concern); header handling (O-RT);
// nor that scrubbing preserves any operator-useful signal beyond the one code.
func assertScrubbedBodyLaws(t *testing.T, where string, original []byte, out string) string {
	t.Helper()
	// L1
	if !json.Valid([]byte(out)) {
		t.Fatalf("%s: O-SCRUB L1 violated: scrubbed body is not valid JSON: %q (original=%q)", where, out, original)
	}
	// L2
	dec := json.NewDecoder(bytes.NewReader([]byte(out)))
	dec.DisallowUnknownFields()
	var shape scrubbedShape
	if err := dec.Decode(&shape); err != nil {
		t.Fatalf("%s: O-SCRUB L2 violated: scrubbed body is not exactly {\"error\":{\"code\",\"message\"}}: %q (%v)", where, out, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("%s: O-SCRUB L2 violated: scrubbed body has trailing content after the object: %q", where, out)
	}
	if shape.Error.Message != scrubMessage {
		t.Fatalf("%s: O-SCRUB L2 violated: message is %q, want fixed %q (original=%q)", where, shape.Error.Message, scrubMessage, original)
	}
	code := shape.Error.Code
	// L3
	if !refErrorCodeRe.MatchString(code) {
		t.Fatalf("%s: O-SCRUB L3 violated: emitted code %q contains bytes outside [A-Za-z0-9_.-] or bad length — an attacker byte escaped into the body the SDK parses (original=%q)", where, code, original)
	}
	// L4
	ref, present := refExtractErrorCode(original)
	refClean := present && refErrorCodeRe.MatchString(ref)
	switch {
	case refClean && code != ref:
		t.Fatalf("%s: O-SCRUB L4 violated: input carried charset-clean error.code %q but output emitted %q (original=%q)", where, ref, code, original)
	case !refClean && code != "UpstreamError":
		t.Fatalf("%s: O-SCRUB L4 violated: input had no charset-clean error.code (present=%v ref=%q) but output emitted %q instead of the UpstreamError sentinel (original=%q)", where, present, ref, code, original)
	}
	// L5
	const maxOut = len(`{"error":{"code":"","message":"upstream error response body suppressed"}}`) + 64
	if len(out) > maxOut {
		t.Fatalf("%s: O-SCRUB L5 violated: scrubbed body length %d exceeds bound %d (original len=%d) — output size is not bounded independent of input", where, len(out), maxOut, len(original))
	}
	return code
}

// ----------------------------------------------------------------------------
// Target 1: FuzzScrubbedErrorBody
// ----------------------------------------------------------------------------

func FuzzScrubbedErrorBody(f *testing.F) {
	for _, s := range []string{
		``,
		`not json`,
		`{}`,
		`{"error":{}}`,
		`{"error":{"code":"SecretNotFound","message":"x"}}`,
		`{"error":{"code":"Forbidden"}}`,
		`{"error":{"code":""}}`,
		`{"error":{"code":"has space"}}`,
		`{"error":{"code":"inject\",\"x\":\"y"}}`,
		`{"error":{"code":12345}}`,
		`{"error":{"code":"` + "a" + `"}}`,
		`{"error":{"code":"ThisCodeIsWayTooLongToBeAcceptedByTheSixtyFourByteCapRuleRight0000"}}`,
		`{"error":{"code":"ok"},"error":{"code":"second"}}`,
		`{"error":{"Code":"CaseInsensitiveMatch"}}`,           // encoding/json matches tags case-insensitively
		`{"error":{"code":"SecretNotFound"},"extra":[1,2,3]}`, // unknown top-level fields tolerated
		`{"error":"not an object"}`,
		`{"error":{"code":"ünïçödé"}}`,
		"{\"error\":{\"code\":\"a\\u0000b\"}}",
		`[1,2,3]`,
		`{"error":{"code":"a.b-c_d"}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, original []byte) {
		out := scrubbedErrorBody(original)
		assertScrubbedBodyLaws(t, "FuzzScrubbedErrorBody", original, out)
	})
}

// ----------------------------------------------------------------------------
// Target 2: FuzzValidErrorCode — differential vs an independent regexp engine.
//
// Oracle O-CODE: validErrorCode(s) == refErrorCodeRe.MatchString(s) for every s.
// Does NOT verify: whether the charset policy is the RIGHT security choice (a
// policy question), Unicode normalization, or anything about how the code is
// then embedded — only that the implementation matches its stated spec.
// ----------------------------------------------------------------------------

func FuzzValidErrorCode(f *testing.F) {
	for _, s := range []string{
		"", "a", "A", "0", "_", ".", "-",
		"SecretNotFound", "has space", "tab\there", "new\nline",
		"quote\"here", "back\\slash", "ünïçödé", "a\x00b",
		"this_is_exactly_sixty_four_characters_long_padding_padding_paddin0",  // 64
		"this_is_sixty_five_characters_long_padding_padding_padding_paddin00", // 65
		"UpstreamError", "/slash", "a+b", "a=b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := validErrorCode(s)
		want := refErrorCodeRe.MatchString(s)
		if got != want {
			t.Fatalf("O-CODE violated: validErrorCode(%q)=%v, independent regexp=%v", s, got, want)
		}
	})
}

// ----------------------------------------------------------------------------
// Target 3: FuzzCappedBodyReader — content-length / size-cap boundary.
// ----------------------------------------------------------------------------

// chunkedReader feeds body to cappedBodyReader in small pieces so the
// "ask for remaining+1" boundary logic is exercised across Read calls. When
// eofWithData is set it returns io.EOF together with the final bytes (the common
// real-world shape) instead of in a separate zero-byte Read.
type chunkedReader struct {
	data        []byte
	pos         int
	chunk       int
	eofWithData bool
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := min(len(r.data)-r.pos, r.chunk, len(p))
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	if r.pos >= len(r.data) && r.eofWithData {
		return n, io.EOF
	}
	return n, nil
}

// FuzzCappedBodyReader drives cappedBodyReader over a hostile body with a fuzzed
// cap and read schedule and checks oracle O-CAP against a trivial counting model:
//
//	M1  the bytes delivered equal body[:min(len,cap)] EXACTLY (byte-for-byte);
//	M2  (len(body) > cap)  <=>  the terminal error is errResponseTooLarge;
//	M3  no more than cap bytes are ever delivered;
//	M4  the error is sticky: a Read after the terminal error returns (0, sameErr).
//
// Does NOT verify: decompression (the cap sits POST-decompression — a gzip bomb
// is bounded upstream, not here), Close() connection-pool semantics, concurrent
// reads, or caps outside [0, 4MiB] (production MaxBytes is the fixed positive
// constant connectMaxResponseBytes, so a negative cap is unreachable).
func FuzzCappedBodyReader(f *testing.F) {
	f.Add([]byte("hello"), uint32(3), uint16(1), uint16(1), false)
	f.Add([]byte("hello"), uint32(5), uint16(2), uint16(4), true)
	f.Add([]byte(""), uint32(0), uint16(1), uint16(1), false)
	f.Add([]byte("abc"), uint32(0), uint16(1), uint16(1), false)
	f.Add(bytes.Repeat([]byte("x"), 4096), uint32(1024), uint16(7), uint16(13), true)
	f.Fuzz(func(t *testing.T, body []byte, capRaw uint32, chunkRaw, bufRaw uint16, eofWithData bool) {
		const capCeil = 4 << 20
		capN := int64(capRaw % (capCeil + 1))
		chunk := int(chunkRaw%4096) + 1
		bufsz := int(bufRaw%4096) + 1

		cbr := &cappedBodyReader{r: &chunkedReader{data: body, chunk: chunk, eofWithData: eofWithData}, remaining: capN}

		var got []byte
		var finalErr error
		maxIters := len(body) + int(capN) + 16
		for i := 0; ; i++ {
			if i > maxIters {
				t.Fatalf("O-CAP: cappedBodyReader did not terminate after %d reads (body=%d cap=%d chunk=%d buf=%d) — possible infinite loop", i, len(body), capN, chunk, bufsz)
			}
			buf := make([]byte, bufsz)
			n, err := cbr.Read(buf)
			if n < 0 || n > bufsz {
				t.Fatalf("O-CAP: Read returned out-of-range n=%d (buf=%d)", n, bufsz)
			}
			got = append(got, buf[:n]...)
			if err != nil {
				finalErr = err
				break
			}
		}

		// Reference model.
		lim := min(capN, int64(len(body)))
		want := body[:lim]
		tooLarge := int64(len(body)) > capN

		// M1
		if !bytes.Equal(got, want) {
			t.Fatalf("O-CAP M1 violated: delivered %d bytes, want %d (body=%d cap=%d): %q vs %q", len(got), len(want), len(body), capN, got, want)
		}
		// M3
		if int64(len(got)) > capN {
			t.Fatalf("O-CAP M3 violated: delivered %d bytes exceeds cap %d", len(got), capN)
		}
		// M2
		isTooLarge := errors.Is(finalErr, errResponseTooLarge)
		if tooLarge && !isTooLarge {
			t.Fatalf("O-CAP M2 violated: body(%d) > cap(%d) but terminal error is %v, not errResponseTooLarge", len(body), capN, finalErr)
		}
		if !tooLarge && isTooLarge {
			t.Fatalf("O-CAP M2 violated: body(%d) <= cap(%d) but got errResponseTooLarge", len(body), capN)
		}
		if !tooLarge && finalErr != io.EOF {
			t.Fatalf("O-CAP M2 violated: body(%d) <= cap(%d) should end in io.EOF, got %v", len(body), capN, finalErr)
		}
		// M4 sticky error
		n2, err2 := cbr.Read(make([]byte, bufsz))
		if n2 != 0 || err2 != finalErr {
			t.Fatalf("O-CAP M4 violated: post-terminal Read returned (%d,%v), want (0,%v)", n2, err2, finalErr)
		}
	})
}

// ----------------------------------------------------------------------------
// Target 4: FuzzErrorBodyScrubRoundTrip — content-type / content-length /
// transfer-encoding rewrite on error responses.
// ----------------------------------------------------------------------------

type stubRoundTripper struct{ resp *http.Response }

func (s stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.resp.Request = req
	return s.resp, nil
}

// FuzzErrorBodyScrubRoundTrip builds a hostile *http.Response and runs it through
// errorBodyScrubRoundTripper.RoundTrip. Oracle O-RT:
//
//	for status < 300 (success): the response passes through UNCHANGED (body and
//	  Content-Length preserved) — only error statuses are scrubbed, by design;
//	for status >= 300: the body is replaced by a scrubbedErrorBody value that
//	  satisfies all O-SCRUB laws; Content-Type is forced to application/json;
//	  Content-Length (header and field) equals the new body length; TransferEncoding
//	  is cleared and Uncompressed set; Content-Encoding/Content-Range/Content-Md5
//	  are deleted; the status code and unrelated headers (Retry-After) are kept so
//	  the SDK's retry/auth-challenge decisions are undisturbed.
//
// Does NOT verify: the underlying transport (dial guard, redirect refusal, size
// cap, TLS, HTTP/2) — a stub RoundTripper stands in; real SDK parsing of the
// scrubbed body; nor that draining the original enables keep-alive reuse.
func FuzzErrorBodyScrubRoundTrip(f *testing.F) {
	f.Add(uint16(200), []byte(`{"value":"s"}`), false, false, false, false, false)
	f.Add(uint16(404), []byte(`{"error":{"code":"SecretNotFound"}}`), true, true, true, true, true)
	f.Add(uint16(500), bytes.Repeat([]byte("A"), 8192), true, false, false, true, false)
	f.Add(uint16(301), []byte(`{"error":{"code":"inject\",\"x\":\"y"}}`), false, true, false, false, true)
	f.Add(uint16(503), []byte(``), false, false, false, false, false)
	f.Fuzz(func(t *testing.T, statusRaw uint16, body []byte, ce, cr, md5, te, retryAfter bool) {
		sc := int(statusRaw%550) + 100 // valid-ish HTTP status range 100..649
		mkResp := func() *http.Response {
			h := http.Header{}
			if ce {
				h.Set("Content-Encoding", "gzip")
			}
			if cr {
				h.Set("Content-Range", "bytes 0-1/100")
			}
			if md5 {
				h.Set("Content-Md5", "q1==")
			}
			if retryAfter {
				h.Set("Retry-After", "7")
			}
			resp := &http.Response{
				StatusCode:    sc,
				Header:        h,
				Body:          io.NopCloser(bytes.NewReader(body)),
				ContentLength: int64(len(body)),
			}
			if te {
				resp.TransferEncoding = []string{"chunked"}
			}
			return resp
		}

		req := httptest.NewRequest(http.MethodGet, "https://vault.example.net/secret", nil)
		rt := errorBodyScrubRoundTripper{Transport: stubRoundTripper{resp: mkResp()}}
		out, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("O-RT: RoundTrip returned error %v (should never error on a delivered response)", err)
		}
		if out == nil {
			t.Fatalf("O-RT: RoundTrip returned nil response")
		}
		gotBody, rerr := io.ReadAll(out.Body)
		_ = out.Body.Close()
		if rerr != nil {
			t.Fatalf("O-RT: scrubbed response body is not readable: %v", rerr)
		}

		if sc < 300 {
			// passthrough
			if !bytes.Equal(gotBody, body) {
				t.Fatalf("O-RT passthrough violated: success status %d body changed: %q vs %q", sc, gotBody, body)
			}
			if out.ContentLength != int64(len(body)) {
				t.Fatalf("O-RT passthrough violated: success status %d ContentLength %d != %d", sc, out.ContentLength, len(body))
			}
			return
		}

		// error-status scrub
		assertScrubbedBodyLaws(t, "FuzzErrorBodyScrubRoundTrip", body, string(gotBody))
		if ct := out.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("O-RT violated: Content-Type %q, want application/json (status=%d)", ct, sc)
		}
		if out.ContentLength != int64(len(gotBody)) {
			t.Fatalf("O-RT violated: ContentLength field %d != new body len %d (status=%d)", out.ContentLength, len(gotBody), sc)
		}
		if clh := out.Header.Get("Content-Length"); clh != strconv.Itoa(len(gotBody)) {
			t.Fatalf("O-RT violated: Content-Length header %q != new body len %d (status=%d)", clh, len(gotBody), sc)
		}
		if out.TransferEncoding != nil {
			t.Fatalf("O-RT violated: TransferEncoding not cleared: %v (status=%d)", out.TransferEncoding, sc)
		}
		if !out.Uncompressed {
			t.Fatalf("O-RT violated: Uncompressed not set after scrub (status=%d)", sc)
		}
		for _, hdr := range []string{"Content-Encoding", "Content-Range", "Content-Md5"} {
			if v := out.Header.Get(hdr); v != "" {
				t.Fatalf("O-RT violated: %s not deleted on error scrub: %q (status=%d)", hdr, v, sc)
			}
		}
		if out.StatusCode != sc {
			t.Fatalf("O-RT violated: status code changed from %d to %d", sc, out.StatusCode)
		}
		if retryAfter && out.Header.Get("Retry-After") != "7" {
			t.Fatalf("O-RT violated: Retry-After header dropped on error scrub (status=%d) — SDK retry signal lost", sc)
		}
	})
}
