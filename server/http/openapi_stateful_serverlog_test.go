package http

// openapi_stateful_serverlog_test.go pins the diagnostic the strict no-5xx oracle of
// FuzzOpenAPIStateful relies on (#4786): the handler's own log line, the only place an
// Internal answer names its cause, is captured per request and handed to the failure
// message, and the process-wide logger is put back afterwards.

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOsExec_CapturesServerLogAndRestoresLogger(t *testing.T) {
	var outer bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&outer)
	t.Cleanup(func() { log.SetOutput(prev) })

	w := &osWorld{router: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		log.Printf("Error sharing secret 2: some storage cause")
		rw.WriteHeader(http.StatusInternalServerError)
	})}

	rec := osExec(w, httptest.NewRequest(http.MethodPost, "/api/v1/secrets/2/share", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(osLastServerLog, "Error sharing secret 2: some storage cause") {
		t.Fatalf("osLastServerLog = %q, want the handler's log line", osLastServerLog)
	}
	if outer.Len() != 0 {
		t.Fatalf("the request's log line leaked to the outer logger: %q", outer.String())
	}

	log.Printf("after")
	if !strings.Contains(outer.String(), "after") {
		t.Fatalf("the outer logger was not restored after osExec: %q", outer.String())
	}

	quiet := &osWorld{router: http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })}
	osExec(quiet, httptest.NewRequest(http.MethodGet, "/quiet", nil))
	if osLastServerLog != "" {
		t.Fatalf("a later request must replace the capture, not append to it: %q", osLastServerLog)
	}
}
