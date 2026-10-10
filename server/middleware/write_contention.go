package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
)

// WriteContentionRetryAfterSeconds is the Retry-After the API sends when the
// SQLite write gate timed out. The gate waits up to 10s before giving up, so the
// system is already saturated rather than blipping: a few seconds lets the queue
// drain without the client hammering it (the auth middleware's 2s is for a
// single-read hiccup, not a full gate timeout).
const WriteContentionRetryAfterSeconds = 5

// writeContentionMessage is the entire client-visible explanation: no driver,
// lock, or storage vocabulary, so a 503 cannot be used to fingerprint the
// backend.
const writeContentionMessage = "The service is temporarily busy. Please retry shortly."

// credentialPathPrefix marks the credential surface (login, MFA, WebAuthn login,
// setup/consume, SSO/SAML callbacks, password change). A storage failure there
// AFTER a credential matched must look exactly like a wrong credential (#2740
// option C / #2888); a distinct 503 would confirm the guess. The handlers on this
// prefix own their failure mapping, so the middleware never rewrites it.
const credentialPathPrefix = "/auth/"

// WriteContention turns "the SQLite write gate timed out for this request" into
// a 503 Service Unavailable with Retry-After.
//
// It installs a corestorage.ContentionSignal in the request context. The gate
// marks it when it gives up. If the handler then answers with a plain 500 the
// response is replaced by the fixed 503; every other status is left alone, so a
// handler that swallowed the timeout (best-effort write) and succeeded, or that
// deliberately chose its own status (404/409/502/503), is not second-guessed.
// The credential surface is exempt (see credentialPathPrefix).
//
// Because a request may run several write transactions, a 503 does not promise
// that nothing was written; the API reference says to retry only idempotent
// requests blindly.
func WriteContention(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, credentialPathPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, sig := corestorage.WithContentionSignal(r.Context())
		cw := &contentionWriter{ResponseWriter: w, sig: sig, req: r}
		next.ServeHTTP(cw, r.WithContext(ctx))
	})
}

type contentionWriter struct {
	http.ResponseWriter
	sig     *corestorage.ContentionSignal
	req     *http.Request
	decided bool
	discard bool // the original 500 body is being replaced
}

func (w *contentionWriter) WriteHeader(code int) {
	if w.decided {
		if !w.discard {
			w.ResponseWriter.WriteHeader(code)
		}
		return
	}
	w.decided = true
	if code != http.StatusInternalServerError || !w.sig.Hit() {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.discard = true
	// Logged once, here, where the mapping happens; the handler's own log line
	// (if any) carries the underlying error. No query string: it may hold tokens.
	log.Printf("write gate contention: %s %s answered 503 (Retry-After %ds)", w.req.Method, w.req.URL.Path, WriteContentionRetryAfterSeconds)
	h := w.Header()
	h.Del("Content-Length")
	h.Set(hdrContentType, mimeJSON)
	h.Set("Retry-After", strconv.Itoa(WriteContentionRetryAfterSeconds))
	w.ResponseWriter.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w.ResponseWriter).Encode(map[string]interface{}{
		"success": false,
		"error":   "ServiceUnavailable",
		"message": writeContentionMessage,
		"code":    http.StatusServiceUnavailable,
	})
}

func (w *contentionWriter) Write(p []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.discard {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

// Flush keeps streaming handlers working through the wrapper.
func (w *contentionWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok && !w.discard {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *contentionWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
