package k8ssync

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ERR-ECHO-SWEEP-1: a sweep of the error sites in keyorix_fetcher.go that could carry
// server-controlled bytes into an error returned by Fetch/FetchWithExpiry (#4062).
// TestKeyorixFetcher_ServerFieldsNeverReachErrorText covers the decode errors and
// TestKeyorixFetcher_DuplicateEnvironmentErrorDoesNotEchoServerName the duplicate
// environment list; this test covers the rest of the response surface: the secret-state
// refusal envelope, non-2xx bodies, the environment and secret lists, and the transport.
//
// Each row puts CANARY in one server-controlled position and states whether the
// canary may reach the returned error:
//
//   - wantEcho=false: the canary must not appear (the rule holds).
//   - wantEcho=true:  a KNOWN FINDING, pinned so that the suite stays green on main while
//     the defect is open. The row asserts the echo IS present; when the product code is
//     fixed the row fails with a message saying to flip it to wantEcho=false, which turns
//     it into the regression guard. Finding ids: see the finding field of each row.
//
// What this does NOT verify:
//   - error text built by the standard library or the TLS stack from the server's input
//     beyond the two shapes below (the HTTP/1 status line and the response head): x509
//     certificate names in a verification failure, HTTP/2 frame errors, proxy errors and
//     header parsing errors are not driven here;
//   - numeric echoes (secret, project and environment ids formatted with %d): a uint
//     cannot carry text, so no canary can be placed there; their length is bounded by the
//     decoded type, not by this test;
//   - the sinks: that an error is logged, or what the engine does with it (sync.go wraps
//     it as `fetch %q: %w`), is not checked;
//   - the other connectors (internal/connect, dynamic, rotation, delivery).
func TestKeyorixFetcher_ErrorSitesVsServerControlledBytes(t *testing.T) {
	const canary = "CANARYSWEEP1"

	// serve answers the three request kinds with the given bodies; a nil entry falls back
	// to a well-formed answer for a secret "db" in environment "prod" (id 3).
	type answers struct {
		envs, list, value func(w http.ResponseWriter)
	}
	jsonBody := func(status int, body string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
	}
	okEnvs := jsonBody(200, `{"data":{"environments":[{"ID":3,"Name":"prod"}]}}`)
	okList := jsonBody(200, `{"data":{"secrets":[{"ID":7,"Name":"db","project_id":1,"environment_id":3}],"total_pages":1}}`)
	handler := func(a answers) http.Handler {
		pick := func(f func(http.ResponseWriter), def func(http.ResponseWriter)) func(http.ResponseWriter) {
			if f != nil {
				return f
			}
			return def
		}
		okValue := jsonBody(200, `{"data":{"value":"v","secret":{"id":7,"project_id":1,"environment_id":3}}}`)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/environments"):
				pick(a.envs, okEnvs)(w)
			case r.URL.Path == "/api/v1/secrets":
				pick(a.list, okList)(w)
			default:
				pick(a.value, okValue)(w)
			}
		})
	}

	// rawServer answers every connection with raw bytes instead of an HTTP response.
	rawServer := func(t *testing.T, reply string) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(reply))
				_ = c.Close()
			}
		}()
		return "http://" + ln.Addr().String()
	}

	redirect := func(location string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
		}
	}

	cases := []struct {
		name     string
		finding  string // "" for a row that documents a site that is fine
		wantEcho bool
		a        answers
		raw      string // when set, the server answers with these raw bytes instead
	}{
		// --- the secret-state refusal envelope (secretStateRefusal) ---
		{name: "refusal envelope: unknown error code on 409", a: answers{value: jsonBody(409, `{"error":"`+canary+`","details":{"x":"`+canary+`"}}`)}},
		{name: "refusal envelope: unknown error code on 403", a: answers{value: jsonBody(403, `{"error":"`+canary+`"}`)}},
		// The switch matches env.Error exactly, so the %q-formatted code is always one of the
		// four constants; a known code with a suffix is not matched and is not echoed.
		{name: "refusal envelope: known code plus canary suffix", a: answers{value: jsonBody(409, `{"error":"SecretSuspended`+canary+`"}`)}},
		{name: "refusal envelope: details of the wrong type", a: answers{value: jsonBody(409, `{"error":"SecretSuspended","details":"`+canary+`"}`)}},

		// --- non-2xx answers: only the status code is reported ---
		{name: "401 body", a: answers{envs: jsonBody(401, `{"error":"`+canary+`"}`)}},
		{name: "404 body", a: answers{value: jsonBody(404, `{"error":"`+canary+`"}`)}},
		{name: "418 body", a: answers{list: jsonBody(418, canary)}},
		{name: "500 body", a: answers{envs: jsonBody(500, canary)}},

		// --- environment list ---
		{name: "environment list: other names", a: answers{envs: jsonBody(200, `{"data":{"environments":[{"ID":9,"Name":"`+canary+`"}]}}`)}},
		{name: "environment list: id zero", a: answers{envs: jsonBody(200, `{"data":{"environments":[{"ID":0,"Name":"prod","extra":"`+canary+`"}]}}`)}},

		// --- secret list ---
		{name: "secret list: other names, page count over the cap", a: answers{list: jsonBody(200, `{"data":{"secrets":[{"ID":8,"Name":"`+canary+`","project_id":1,"environment_id":3}],"total_pages":5000}}`)}},
		{name: "secret list: matching name under another scope", a: answers{list: jsonBody(200, `{"data":{"secrets":[{"ID":7,"Name":"db","project_id":2,"environment_id":4,"x":"`+canary+`"}],"total_pages":1}}`)}},
		{name: "secret list: matching name listed twice", a: answers{list: jsonBody(200, `{"data":{"secrets":[{"ID":7,"Name":"db","project_id":1,"environment_id":3},{"ID":8,"Name":"db","project_id":1,"environment_id":3,"x":"`+canary+`"}],"total_pages":1}}`)}},

		// --- secret value ---
		{name: "value: answer for another secret", a: answers{value: jsonBody(200, `{"data":{"value":"v","secret":{"id":99,"project_id":5,"environment_id":6},"x":"`+canary+`"}}`)}},
		{name: "value: empty value", a: answers{value: jsonBody(200, `{"data":{"value":"","secret":{"id":7,"project_id":1,"environment_id":3},"x":"`+canary+`"}}`)}},

		// --- transport: KNOWN FINDINGS ---
		// refuseRedirect formats netutil.RedactURLHost(Location), but classifyTransportError
		// wraps the http.Client error, whose *url.Error layer prints the redirect target in
		// full ("Get \"<Location>\": ..."): host, path and query are all server-controlled
		// and reach the error, and the host survives even RedactURLHost.
		{name: "redirect Location host", finding: "ERR-ECHO-1", wantEcho: true,
			a: answers{envs: redirect("http://" + canary + ".example/")}},
		{name: "redirect Location query", finding: "ERR-ECHO-1", wantEcho: true,
			a: answers{envs: redirect("http://example.invalid/p?token=" + canary)}},
		// net/http builds these texts from the bytes the server sent and
		// classifyTransportError wraps the error with %w.
		{name: "malformed status line", finding: "ERR-ECHO-2", wantEcho: true,
			raw: "HTTP/1.1 " + canary + " OK\r\n\r\n"},
		{name: "malformed response head", finding: "ERR-ECHO-2", wantEcho: true,
			raw: canary + "\r\n\r\n"},
	}

	for _, tc := range cases {
		for _, via := range []string{"FetchWithExpiry", "Fetch"} {
			t.Run(tc.name+"/"+via, func(t *testing.T) {
				var base string
				if tc.raw != "" {
					base = rawServer(t, tc.raw)
				} else {
					srv := httptest.NewServer(handler(tc.a))
					defer srv.Close()
					base = srv.URL
				}

				f := NewKeyorixFetcher(base, "tok", 1)
				var err error
				if via == "Fetch" {
					_, err = f.Fetch(context.Background(), "prod/db")
				} else {
					_, _, err = f.FetchWithExpiry(context.Background(), "prod/db")
				}
				if err == nil {
					t.Fatalf("expected an error")
				}
				echoed := strings.Contains(err.Error(), canary)
				switch {
				case tc.wantEcho && !echoed:
					t.Fatalf("known finding %s no longer reproduces: the canary is gone from the error, so it is fixed; set wantEcho=false on this row to make it a regression guard: %v", tc.finding, err)
				case !tc.wantEcho && echoed:
					t.Fatalf("server-controlled text reached the error (#4062): %v", err)
				}
			})
		}
	}
}
