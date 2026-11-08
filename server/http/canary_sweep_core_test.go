package http

// canary_sweep_core_test.go -- harness for the route-sweep secret-leak canary
// oracle (internal/canary/PREREG.md). It drives EVERY route the live chi router
// registers, as several principals, with canaries (secret-class S, metadata
// control M, hostile charset and plain) injected into every request surface,
// and scans every output surface it can see: response bodies and headers,
// server log, stdout, stderr, /metrics, every cell of every DB table
// (audit_events included), the raw SQLite file and its WAL, and temp files.
//
// It complements FuzzCanarySecretLeakage (canary_secret_leakage_fuzz_test.go),
// which drives a curated operation set; it reuses that file's world builder.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/canary"
	"github.com/keyorixhq/keyorix/internal/core"
)

const (
	sweepAdminPassword = "TestPassword123!"
	sweepMaxFileBytes  = 32 << 20
)

// sweepSecretKeys are request field / query / header names that carry
// secret-class values. Everything else is metadata.
var sweepSecretKeys = map[string]bool{
	"value": true, "secret": true, "password": true, "new_password": true, "current_password": true,
	"old_password": true, "token": true, "api_key": true, "apikey": true, "dsn": true, "admin_dsn": true,
	"connection_string": true, "private_key": true, "passphrase": true, "client_secret": true,
	"credential": true, "recovery_code": true, "code": true, "otp": true, "key": true, "secret_value": true,
	"url": true, "webhook_url": true, "authorization": true, "cookie": true, "session_token": true,
}

var sweepMetaKeys = []string{"name", "description", "email", "username", "display_name", "note", "comment", "reason", "title", "path", "ref", "label", "tag", "id", "type", "project", "environment"}

// sweepDestructive routes would end a session, change a password, or purge
// evidence, silently turning the rest of the sweep into an unauthenticated
// one. The long-lived admin and outsider sessions never drive them: a throw-away
// principal does (useDisposable), alongside the anon and garbage principals.
var sweepDestructive = regexp.MustCompile(`(?i)(/auth/logout|/auth/refresh|/auth/change-password|/auth/mfa/|/auth/webauthn/|/admin/impersonate|/auth/end-impersonation|/jobs/purge|/legal-hold|/system/init|/auth/password-reset|/auth/tokens/expired|/audit/migrate-chain-encoding)`)

type sweepReq struct {
	Method, Target string
	Header         http.Header
	Body           []byte
	Principal      string
	Shape          string
	Route          string
	RemoteAddr     string
}

// Repro is the JSON form written into a finding.
func (r sweepReq) Repro() map[string]any {
	h := map[string]string{}
	for k, v := range r.Header {
		h[k] = strings.Join(v, ",")
	}
	// A session bearer is replaced: a finding file must not carry a live
	// credential. The anon and garbage principals only ever carry canaries.
	if _, ok := h["Authorization"]; ok && r.Principal != "anon" && r.Principal != "garbage" {
		h["Authorization"] = "Bearer <" + r.Principal + "-session>"
	}
	return map[string]any{"method": r.Method, "target": r.Target, "headers": h, "body_hex": hex.EncodeToString(r.Body), "principal": r.Principal, "shape": r.Shape}
}

type sweepHitRec struct {
	Key     string         `json:"key"`
	Surface string         `json:"surface"`
	Route   string         `json:"route"`
	Label   string         `json:"label"`
	Variant string         `json:"variant"`
	Class   string         `json:"class"`
	Snippet string         `json:"snippet"`
	Status  int            `json:"status,omitempty"`
	Repro   map[string]any `json:"repro,omitempty"`
	Count   int            `json:"count"`
	Waiver  string         `json:"waiver,omitempty"`
}

// sweepWaiver permits one exact (route, label, surface) hit. Anything not
// named here is a finding. A row on the log surface applies only to the access
// log record of the request that carried the canary, and only to the request
// URI inside that record (accessLogURI), so a handler logging the same value is
// still caught. Kind is sweepWaiverOpenDefect (Ref names the issue; remove the
// row when it is fixed) or sweepWaiverContract (the API returns this value to
// this principal by design). TestCanaryRouteSweep fails on a row no hit used.
type sweepWaiver struct {
	ID, Route, Label, Surface, Principal string
	Kind, Ref, Why                       string
}

const (
	sweepWaiverOpenDefect = "open-defect"
	sweepWaiverContract   = "contract"
)

var sweepWaivers = []sweepWaiver{
	{
		ID: "setup-encoded-slash", Route: "GET /auth/setup/{token}", Label: "token-h", Surface: "log",
		Kind: sweepWaiverOpenDefect, Ref: "#4045",
		Why: "redaction stops at an encoded slash; a server-minted token is hex and cannot contain one. Remove when #4045 is fixed.",
	},
	{
		ID: "channel-create-url", Route: "POST /api/v1/notification-channels", Label: "stored-webhook", Surface: "resp-body", Principal: "admin",
		Kind: sweepWaiverContract, Ref: "#3425",
		Why: "the create response is the one place the full URL is returned to the admin who supplied it; every other response elides it.",
	},
}

// staleWaivers lists the rows no hit used.
func (s *sweep) staleWaivers() []string {
	var out []string
	for _, w := range sweepWaivers {
		if !s.usedWaivers[w.ID] {
			out = append(out, w.ID)
		}
	}
	return out
}

type outCapture struct {
	r, w *os.File
	buf  bytes.Buffer
	mu   sync.Mutex
	done chan struct{}
}

func newOutCapture() (*outCapture, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	c := &outCapture{r: r, w: w, done: make(chan struct{})}
	go func() {
		b := make([]byte, 32<<10)
		for {
			n, err := r.Read(b)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(b[:n])
				c.mu.Unlock()
			}
			if err != nil {
				close(c.done)
				return
			}
		}
	}()
	return c, nil
}

func (c *outCapture) drain() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := append([]byte(nil), c.buf.Bytes()...)
	c.buf.Reset()
	return b
}

func (c *outCapture) close() { _ = c.w.Close(); <-c.done; _ = c.r.Close() }

type sweep struct {
	w       *canaryWorld
	seed    uint64
	sc      *canary.Scanner
	byLabel map[string]canary.Canary
	hits    map[string]*sweepHitRec
	nreq    int
	statusN map[int]int
	metaSeen,
	persistedSeen map[string]bool
	stdout, stderr   *outCapture
	origOut, origErr *os.File
	start            time.Time
	tmpDir, prevTmp  string
	hadTmp           bool
	outsiderTok      string
	dispN            int
	usedWaivers      map[string]bool
	// scanFailures lists every surface the oracle could not read; any entry makes
	// the run INVALID, because an unread surface would look like a clean one.
	scanFailures []string
	// current request context for attribution
	cur *sweepReq
}

func newSweep(t testing.TB, seed uint64) *sweep {
	// A private TMPDIR for the whole process under test: every os.CreateTemp /
	// os.MkdirTemp("") call the server makes lands here, so the temp-file
	// surface is scanned exhaustively instead of sampling the shared system
	// temp directory.
	tmp, err := os.MkdirTemp("", "kx-sweep-tmp-*")
	if err != nil {
		t.Fatalf("private tmpdir: %v", err)
	}
	prevTmp, hadTmp := os.LookupEnv("TMPDIR")
	_ = os.Setenv("TMPDIR", tmp)
	w := buildCanaryWorld(t)
	s := &sweep{w: w, tmpDir: tmp, prevTmp: prevTmp, hadTmp: hadTmp, seed: seed, sc: canary.NewScanner(), byLabel: map[string]canary.Canary{}, hits: map[string]*sweepHitRec{},
		statusN: map[int]int{}, metaSeen: map[string]bool{}, persistedSeen: map[string]bool{}, usedWaivers: map[string]bool{}, start: time.Now()}
	s.outsiderTok = w.principals[2].token
	// Secret-class canaries, each in a plain and a hostile-charset shape.
	for _, l := range []string{"value", "password", "token", "dsn", "apikey", "privkey", "authhdr", "cookie", "query", "url", "code", "secret"} {
		s.register(canary.New(l, canary.Secret, seed, false))
		s.register(canary.New(l+"-h", canary.Secret, seed, true))
	}
	for _, l := range append([]string{"pathparam", "requestid", "ua"}, sweepMetaKeys...) {
		s.register(canary.New("m-"+l, canary.Metadata, seed, strings.HasSuffix(l, "e")))
	}
	// The live admin and outsider session tokens and a fresh PAT are credentials
	// too: after the request that used them they must never come back.
	s.registerRaw("admin-session", w.adminTok)
	s.registerRaw("outsider-session", s.outsiderTok)
	if pat, err := w.c.CreateOwnPAT(context.Background(), w.principals[0].id, "sweep-pat", nil, []string{"secrets.read"}, 0, 0, nil); err == nil && pat != nil {
		s.registerRaw("pat-readera", pat.PlainToken)
	}
	// Capture stdout / stderr for the lifetime of the sweep.
	s.origOut, s.origErr = os.Stdout, os.Stderr
	if c, err := newOutCapture(); err == nil {
		s.stdout = c
		os.Stdout = c.w
	}
	if c, err := newOutCapture(); err == nil {
		s.stderr = c
		os.Stderr = c.w
	}
	if err := s.seedStoredSecrets(); err != nil {
		s.close()
		t.Fatalf("INVALID RUN: %v", err)
	}
	return s
}

// sweepSuccessPaths are the typed requests that really store a secret-class
// value. The generated shapes only fill strings, so without these every create
// route is rejected before core and the at-rest scans have nothing to find.
func (s *sweep) sweepSuccessPaths() []struct {
	route, label string
	body         map[string]any
} {
	const secrets, dynamic, channels = "POST /api/v1/secrets/", "POST /api/v1/dynamic-secrets/configs", "POST /api/v1/notification-channels"
	name := func(suffix string) string { return s.byLabel["m-stored-name"].Raw + "-" + suffix }
	return []struct {
		route, label string
		body         map[string]any
	}{
		{secrets, "value", map[string]any{"name": name("plain"), "value": s.byLabel["value"].Raw, "project_id": s.w.projAID, "environment_id": s.w.envAID, "type": "password"}},
		{secrets, "value-h", map[string]any{"name": name("hostile"), "value": s.byLabel["value-h"].Raw, "project_id": s.w.projAID, "environment_id": s.w.envAID, "type": "password"}},
		{dynamic, "dsn", map[string]any{"name": name("dyn"), "project_id": s.w.projAID, "environment_id": s.w.envAID, "backend_type": "fake", "admin_dsn": "postgres://admin:" + s.byLabel["dsn"].Raw + "@db.internal:5432/app", "default_ttl_seconds": 3600}},
		{channels, "stored-webhook", map[string]any{"name": name("hook"), "type": "webhook", "enabled": false, "events": "secret.rotated", "url": "https://1.1.1.1/hooks/" + s.byLabel["stored-webhook"].Raw}},
	}
}

// seedStoredSecrets drives sweepSuccessPaths through the real router before the
// route sweep, so every later list, search, export and audit route runs with
// these values stored and the at-rest scans cover them. A rejected request is an
// error: the at-rest claim would otherwise be vacuous, as it was when only the
// fixture's own secrets existed.
func (s *sweep) seedStoredSecrets() error {
	s.register(canary.New("m-stored-name", canary.Metadata, s.seed, false))
	s.register(canary.New("stored-webhook", canary.Secret, s.seed, false))
	for _, p := range s.sweepSuccessPaths() {
		b, err := json.Marshal(p.body)
		if err != nil {
			return err
		}
		method, target, _ := strings.Cut(p.route, " ")
		h := http.Header{}
		h.Set("Authorization", "Bearer "+s.w.adminTok)
		h.Set("Content-Type", "application/json")
		r := sweepReq{Method: method, Target: target, Header: h, Body: b, Principal: "admin", Shape: "stored-" + p.label, Route: p.route}
		if code := s.run(r); code < 200 || code > 299 {
			return fmt.Errorf("success-path %s (%s) returned %d, so the %s canary was never stored", p.route, p.label, code, p.label)
		}
	}
	// Assert the effect, not the status: the rows must exist.
	var n int64
	if err := s.w.db.Raw("SELECT COUNT(*) FROM secret_nodes WHERE name LIKE ?", s.byLabel["m-stored-name"].Raw+"-%").Scan(&n).Error; err != nil {
		return fmt.Errorf("counting stored secrets: %w", err)
	}
	if n != 2 {
		return fmt.Errorf("success-path secrets stored %d rows, want 2", n)
	}
	return nil
}

// sessionLive reports whether a bearer token still authenticates.
func (s *sweep) sessionLive(tok string) bool {
	req := httptest.NewRequest("GET", "/api/v1/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.w.router.ServeHTTP(rec, req)
	return rec.Code == http.StatusOK
}

// failScan records a surface the oracle could not read.
func (s *sweep) failScan(format string, args ...any) {
	s.scanFailures = append(s.scanFailures, fmt.Sprintf(format, args...))
}

// useDisposable points r at a fresh throw-away session, for a destructive route.
func (s *sweep) useDisposable(r *sweepReq) bool {
	tok, ok := s.disposable(s.dispN)
	s.dispN++
	if !ok {
		s.failScan("could not create a disposable principal for %s", r.Route)
		return false
	}
	r.Principal = "disposable"
	r.Header.Set("Authorization", "Bearer "+tok)
	return true
}

func (s *sweep) close() {
	if s.stdout != nil {
		os.Stdout = s.origOut
		s.stdout.close()
	}
	if s.stderr != nil {
		os.Stderr = s.origErr
		s.stderr.close()
	}
	s.w.close()
	if s.hadTmp {
		_ = os.Setenv("TMPDIR", s.prevTmp)
	} else {
		_ = os.Unsetenv("TMPDIR")
	}
	_ = os.RemoveAll(s.tmpDir)
}

func (s *sweep) register(c canary.Canary) {
	s.sc.Add(c)
	s.byLabel[c.Label] = c
}

func (s *sweep) registerRaw(label, raw string) {
	if len(raw) < canary.WindowLen*2 {
		return
	}
	c := canary.Canary{Label: label, Class: canary.Secret, Raw: raw, Core: raw[len(raw)-24:]}
	s.register(c)
}

// sCan / mCan pick a canary for a field name; alt flips plain/hostile so both
// shapes are exercised across shapes.
func (s *sweep) fieldCanary(key string, alt bool) canary.Canary {
	k := strings.ToLower(key)
	if sweepIDName.MatchString(key) {
		return s.byLabel["m-id"]
	}
	if sweepSecretKeys[k] || strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") {
		l := map[string]string{"value": "value", "secret": "secret", "password": "password", "new_password": "password", "current_password": "password",
			"token": "token", "api_key": "apikey", "apikey": "apikey", "dsn": "dsn", "admin_dsn": "dsn", "connection_string": "dsn",
			"private_key": "privkey", "url": "url", "webhook_url": "url", "code": "code", "otp": "code", "recovery_code": "code"}[k]
		if l == "" {
			l = "secret"
		}
		if alt {
			l += "-h"
		}
		return s.byLabel[l]
	}
	l := "m-name"
	for _, m := range sweepMetaKeys {
		if m == k {
			l = "m-" + m
		}
	}
	return s.byLabel[l]
}

// ---- request construction -----------------------------------------------

var sweepParam = regexp.MustCompile(`\{[^}]*\}`)

// sweepIDName matches identifier fields and path params (id, token_id, tokenId,
// leaseID, ids). An identifier names a credential, it is not one, however the
// rest of its name reads.
var sweepIDName = regexp.MustCompile(`(?:^|_)[iI][dD][sS]?$|[a-z]I[dD][sS]?$`)

func (s *sweep) path(route string, alt bool) string {
	return sweepParam.ReplaceAllStringFunc(route, func(p string) string {
		name := strings.Trim(p, "{}")
		c := s.fieldCanary(name, alt)
		lower := strings.ToLower(name)
		if c.Class != canary.Secret || (!sweepSecretKeys[lower] && !strings.Contains(lower, "token")) {
			c = s.byLabel["m-pathparam"]
		}
		return url.PathEscape(c.Raw)
	})
}

func (s *sweep) bodyKeys() []string {
	keys := make([]string, 0, len(sweepSecretKeys)+len(sweepMetaKeys))
	for k := range sweepSecretKeys {
		keys = append(keys, k)
	}
	keys = append(keys, sweepMetaKeys...)
	sort.Strings(keys)
	return keys
}

func (s *sweep) jsonObject(alt bool) map[string]any {
	m := map[string]any{}
	for _, k := range s.bodyKeys() {
		m[k] = s.fieldCanary(k, alt).Raw
	}
	return m
}

func (s *sweep) shapesFor(route sweepRoute, principal string) []sweepReq {
	var out []sweepReq
	base := func(shape string, alt bool) sweepReq {
		h := http.Header{}
		switch principal {
		case "admin":
			h.Set("Authorization", "Bearer "+s.w.adminTok)
		case "outsider":
			h.Set("Authorization", "Bearer "+s.outsiderTok)
		case "garbage":
			h.Set("Authorization", "Bearer "+s.fieldCanary("authhdr", alt).Raw)
		}
		return sweepReq{Method: route.Method, Header: h, Principal: principal, Shape: shape, Route: route.String(), Target: s.path(route.Pattern, alt)}
	}
	mk := func(shape string, alt bool, f func(*sweepReq)) {
		r := base(shape, alt)
		f(&r)
		out = append(out, r)
	}
	body := func(alt bool) []byte { b, _ := json.Marshal(s.jsonObject(alt)); return b }
	hasBody := route.Method == "POST" || route.Method == "PUT" || route.Method == "PATCH" || route.Method == "DELETE"
	q := func(alt bool) string {
		v := url.Values{}
		for _, k := range []string{"ref", "q", "token", "password", "secret", "key", "id", "name", "api_key", "value", "code", "search", "filter"} {
			v.Set(k, s.fieldCanary(k, alt).Raw)
		}
		return v.Encode()
	}
	mk("query", false, func(r *sweepReq) { r.Target += "?" + q(false) })
	mk("query-h", true, func(r *sweepReq) { r.Target += "?" + q(true) })
	mk("headers", false, func(r *sweepReq) {
		r.Header.Set("X-Request-Id", s.byLabel["m-requestid"].Raw)
		r.Header.Set("User-Agent", s.byLabel["m-ua"].Raw)
		r.Header.Set("X-Api-Key", s.byLabel["apikey"].Raw)
		r.Header.Set("Cookie", "session="+url.QueryEscape(s.byLabel["cookie"].Raw)+"; csrf="+url.QueryEscape(s.byLabel["cookie-h"].Raw))
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.Header.Set("X-Keyorix-Token", s.byLabel["token"].Raw)
	})
	if principal == "anon" || principal == "garbage" {
		mk("basic-auth", false, func(r *sweepReq) {
			r.Header.Set("Authorization", "Basic "+basicAuth("user", s.byLabel["password"].Raw))
		})
	}
	if hasBody {
		mk("json-full", false, func(r *sweepReq) { r.Body = body(false); r.Header.Set("Content-Type", "application/json") })
		mk("json-full-h", true, func(r *sweepReq) { r.Body = body(true); r.Header.Set("Content-Type", "application/json") })
		mk("json-nested", false, func(r *sweepReq) {
			o := map[string]any{"data": s.jsonObject(false), "items": []any{s.jsonObject(true)}, "config": map[string]any{"credentials": s.jsonObject(false)}}
			r.Body, _ = json.Marshal(o)
			r.Header.Set("Content-Type", "application/json")
		})
		mk("json-trunc", true, func(r *sweepReq) {
			b := body(true)
			i := bytes.Index(b, []byte(`"password":"`))
			if i < 0 {
				i = len(b) / 2
			}
			r.Body = b[:min(len(b), i+12+len(s.byLabel["password-h"].Raw)/2)]
			r.Header.Set("Content-Type", "application/json")
		})
		mk("bad-utf8", false, func(r *sweepReq) {
			r.Body = []byte(`{"value":"` + s.byLabel["value"].Raw + "\xff\xfe\xc3" + `","password":"` + s.byLabel["password-h"].Raw + "\x00\"}")
			r.Header.Set("Content-Type", "application/json")
		})
		mk("dup-keys", false, func(r *sweepReq) {
			r.Body = []byte(`{"value":"` + s.byLabel["value"].Raw + `","value":"` + s.byLabel["value-h"].Raw + `","password":1,"password":["` + s.byLabel["password"].Raw + `"]}`)
			r.Header.Set("Content-Type", "application/json")
		})
		mk("text-plain", false, func(r *sweepReq) {
			r.Body = []byte("value=" + s.byLabel["value"].Raw + "\npassword=" + s.byLabel["password-h"].Raw)
			r.Header.Set("Content-Type", "text/plain")
		})
		mk("form", true, func(r *sweepReq) {
			v := url.Values{}
			for _, k := range s.bodyKeys() {
				v.Set(k, s.fieldCanary(k, true).Raw)
			}
			r.Body = []byte(v.Encode())
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		})
		mk("xml", false, func(r *sweepReq) {
			r.Body = []byte(`<?xml version="1.0"?><Envelope><Password>` + s.byLabel["password"].Raw + `</Password><Name>` + s.byLabel["m-name"].Raw + `</Name><!-- ` + s.byLabel["secret"].Raw + ` --></Envelope>`)
			r.Header.Set("Content-Type", "application/xml")
		})
	}
	return out
}

func basicAuth(u, p string) string {
	return base64Std([]byte(u + ":" + p))
}

// ---- driving + scanning ---------------------------------------------------

func (s *sweep) do(r sweepReq) (*httptest.ResponseRecorder, bool) {
	var rdr io.Reader
	if r.Body != nil {
		rdr = bytes.NewReader(r.Body)
	}
	var req *http.Request
	func() {
		defer func() {
			if x := recover(); x != nil { // httptest.NewRequest panics on an unparsable target
				req = nil
			}
		}()
		req = httptest.NewRequest(r.Method, r.Target, rdr)
	}()
	if req == nil {
		return nil, false
	}
	req.Header = r.Header.Clone()
	req.RemoteAddr = r.RemoteAddr
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if x := recover(); x != nil {
				// A panic that escapes the Recovery middleware is itself a leak
				// surface: its text is attributed to a synthetic surface.
				s.scan("panic-escaped", r.Route, &r, []byte(fmt.Sprint(x)), 0)
			}
		}()
		s.w.router.ServeHTTP(rec, req)
	}()
	return rec, true
}

func (s *sweep) scan(surface, route string, req *sweepReq, hay []byte, status int) {
	for _, h := range s.sc.Scan(surface, hay) {
		s.record(h, route, req, status, "")
	}
}

// scanLog scans drained log output one line at a time, so a waiver can tell the
// access log record of a request from any other line.
func (s *sweep) scanLog(route string, req *sweepReq, blob []byte, status int) {
	for line := range bytes.SplitSeq(blob, []byte("\n")) {
		for _, h := range s.sc.Scan("log", line) {
			s.record(h, route, req, status, s.waiverFor(h, route, req, line, status))
		}
	}
}

// record files one hit. A waived hit keeps a separate key, so it can never hide
// an unwaived hit of the same canary on the same route.
func (s *sweep) record(h canary.Hit, route string, req *sweepReq, status int, waiver string) {
	if h.Class == canary.Metadata {
		s.metaSeen[h.Surface+"|"+h.Label] = true
		return
	}
	if waiver == "" && h.Surface != "log" {
		waiver = s.waiverFor(h, route, req, nil, status)
	}
	key := strings.Join([]string{h.Surface, route, h.Label, h.Variant}, "|")
	if waiver != "" {
		key += "|waived:" + waiver
		s.usedWaivers[waiver] = true
	}
	if rec, ok := s.hits[key]; ok {
		rec.Count++
		return
	}
	rec := &sweepHitRec{Key: key, Surface: h.Surface, Route: route, Label: h.Label, Variant: h.Variant, Class: h.Class.String(), Snippet: h.Snippet, Status: status, Count: 1, Waiver: waiver}
	if req != nil {
		rec.Repro = req.Repro()
	}
	s.hits[key] = rec
}

// waiverFor returns the id of the row in sweepWaivers that permits h, or "".
func (s *sweep) waiverFor(h canary.Hit, route string, req *sweepReq, line []byte, status int) string {
	if h.Class != canary.Secret || req == nil {
		return ""
	}
	for _, w := range sweepWaivers {
		if w.Route != route || w.Label != h.Label || w.Surface != h.Surface || (w.Principal != "" && w.Principal != req.Principal) {
			continue
		}
		if w.Surface == "log" {
			c, ok := s.byLabel[h.Label]
			lo, hi, isAccess := accessLogURI(line, req, status)
			if !ok || c.Core == "" || !strings.Contains(req.Target, c.Core) || !isAccess || h.Offset < lo || h.Offset >= hi {
				continue
			}
		}
		return w.ID
	}
	return ""
}

// accessLogURI returns the byte range of the request URI when line is the
// access log record of req with this exact method, peer address and status
// (chi's DefaultLogFormatter layout, see server/middleware/logger.go).
func accessLogURI(line []byte, req *sweepReq, status int) (lo, hi int, ok bool) {
	re, err := regexp.Compile(`^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} )?(?:\[[^\]]*\] )?"` + regexp.QuoteMeta(req.Method) +
		` http://example\.com(/.*) HTTP/1\.1" from ` + regexp.QuoteMeta(req.RemoteAddr) + ` - ` + strconv.Itoa(status) + ` \d+B in \S+$`)
	if err != nil {
		return 0, 0, false
	}
	m := re.FindSubmatchIndex(line)
	if m == nil {
		return 0, 0, false
	}
	return m[2], m[3], true
}

// nextAddr gives each request its own peer address, so per-IP rate limits do not
// turn the later shapes of a route into 429s that never reach its handler.
func (s *sweep) nextAddr() string {
	return fmt.Sprintf("198.18.%d.%d:4242", (s.nreq>>8)&0xff, s.nreq&0xff)
}

// run drives one request, scans the response and the log it produced, and
// returns the status (0 when the target could not be parsed).
func (s *sweep) run(r sweepReq) int {
	r.RemoteAddr = s.nextAddr()
	s.cur = &r
	s.nreq++
	rec, ok := s.do(r)
	if !ok {
		s.statusN[-1]++
		return 0
	}
	s.statusN[rec.Code]++
	s.scan("resp-body", r.Route, &r, rec.Body.Bytes(), rec.Code)
	var hb strings.Builder
	for k, v := range rec.Header() {
		hb.WriteString(k + ": " + strings.Join(v, ", ") + "\n")
	}
	s.scan("resp-header", r.Route, &r, []byte(hb.String()), rec.Code)
	s.scanLog(r.Route, &r, s.w.drainLog(), rec.Code)
	if s.stdout != nil {
		s.scan("stdout", r.Route, &r, s.stdout.drain(), rec.Code)
	}
	if s.stderr != nil {
		s.scan("stderr", r.Route, &r, s.stderr.drain(), rec.Code)
	}
	// Harvest freshly minted credentials: first sighting is the minting
	// response and is allowed; any later sighting is scanned like a canary.
	if r.Principal == "admin" || r.Principal == "outsider" {
		s.harvest(rec.Body.Bytes())
	}
	return rec.Code
}

var sweepTokenRe = regexp.MustCompile(`\bkx_[a-z_]+_[A-Za-z0-9_\-]{12,}`)

func (s *sweep) harvest(body []byte) {
	for _, m := range sweepTokenRe.FindAll(body, 8) {
		s.registerRaw("harvested-"+string(m[:min(len(m), 14)]), string(m))
	}
	var generic map[string]any
	if json.Unmarshal(body, &generic) == nil {
		for _, k := range []string{"token", "session_token", "access_token", "secret", "plain_token", "recovery_codes"} {
			if v, ok := generic[k].(string); ok && len(v) >= 24 {
				s.registerRaw("harvested-"+k, v)
			}
		}
	}
}

// ---- persistent surfaces ----------------------------------------------------

func (s *sweep) scanPersistent(route string) { s.scanPersistentDeep(route, false) }

func (s *sweep) scanPersistentDeep(route string, deep bool) {
	drainAllBackgroundGoroutines()
	attr := &sweepReq{Route: route, Shape: "after-route"}
	// Output the route's background work wrote after its last request was scanned.
	s.scanLog(route, attr, s.w.drainLog(), 0)
	if s.stdout != nil {
		s.scan("stdout", route, attr, s.stdout.drain(), 0)
	}
	if s.stderr != nil {
		s.scan("stderr", route, attr, s.stderr.drain(), 0)
	}
	// Metrics.
	rec := httptest.NewRecorder()
	mreq := httptest.NewRequest("GET", "/metrics", nil)
	s.w.router.ServeHTTP(rec, mreq)
	s.scan("metrics", route, attr, rec.Body.Bytes(), rec.Code)
	// DB cells.
	sqlDB, err := s.w.db.DB()
	if err != nil {
		s.failScan("db handle after %s: %v", route, err)
	} else {
		s.scanDB(sqlDB, route, attr)
	}
	// Raw file + WAL: the cell scan above already covers live rows; the raw
	// bytes add free-page / WAL remnants, so they are scanned at checkpoints.
	if deep {
		for _, p := range []string{s.w.dbPath, s.w.dbPath + "-wal"} {
			b, err := os.ReadFile(p)
			switch {
			case err == nil:
				s.scanPersistentBytes("dbfile:"+filepath.Base(p), route, attr, b)
			case !errors.Is(err, fs.ErrNotExist): // a WAL exists only between checkpoints
				s.failScan("raw db read %s: %v", filepath.Base(p), err)
			}
		}
	}
	s.scanTemp(route, attr)
}

func (s *sweep) scanPersistentBytes(surface, route string, attr *sweepReq, b []byte) {
	for _, h := range s.sc.Scan(surface, b) {
		if h.Class == canary.Metadata {
			s.metaSeen[surface+"|"+h.Label] = true
			continue
		}
		pk := surface + "|" + h.Label + "|" + h.Variant
		if s.persistedSeen[pk] {
			continue
		}
		s.persistedSeen[pk] = true
		key := strings.Join([]string{h.Surface, route, h.Label, h.Variant}, "|")
		s.hits[key] = &sweepHitRec{Key: key, Surface: h.Surface, Route: route + " (first seen after this route's requests)", Label: h.Label, Variant: h.Variant, Class: h.Class.String(), Snippet: h.Snippet, Count: 1}
	}
}

func (s *sweep) scanDB(db *sql.DB, route string, attr *sweepReq) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		s.failScan("list tables: %v", err)
		return
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			s.failScan("read table name: %v", err)
			continue
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		s.failScan("list tables: %v", err)
	}
	_ = rows.Close()
	for _, tb := range tables {
		r2, err := db.Query(`SELECT * FROM "` + strings.ReplaceAll(tb, `"`, `""`) + `"`)
		if err != nil {
			s.failScan("select %s: %v", tb, err)
			continue
		}
		cols, err := r2.Columns()
		if err != nil {
			s.failScan("columns %s: %v", tb, err)
			_ = r2.Close()
			continue
		}
		for r2.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r2.Scan(ptrs...); err != nil {
				s.failScan("scan row of %s: %v", tb, err)
				break
			}
			for i, v := range vals {
				var b []byte
				switch x := v.(type) {
				case nil:
					continue
				case []byte:
					b = x
				case string:
					b = []byte(x)
				default:
					b = []byte(fmt.Sprint(x))
				}
				if len(b) >= canary.WindowLen {
					s.scanPersistentBytes("db:"+tb+"."+cols[i], route, attr, b)
				}
			}
		}
		if err := r2.Err(); err != nil {
			s.failScan("read rows of %s: %v", tb, err)
		}
		_ = r2.Close()
	}
}

func (s *sweep) scanTemp(route string, attr *sweepReq) {
	// A temp file can disappear between the walk and the read; that is not a
	// blind spot, because the file is gone. Every other failure is one.
	gone := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	err := filepath.WalkDir(s.tmpDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if !gone(err) {
				s.failScan("walk temp %s: %v", p, err)
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fi, e := d.Info()
		if e != nil {
			if !gone(e) {
				s.failScan("stat temp %s: %v", p, e)
			}
			return nil
		}
		if !fi.Mode().IsRegular() || fi.Size() == 0 {
			return nil
		}
		if p == s.w.dbPath || p == s.w.dbPath+"-wal" || p == s.w.dbPath+"-shm" {
			return nil // scanned as dbfile
		}
		if fi.Size() > sweepMaxFileBytes {
			s.failScan("temp file %s is %d bytes, over the %d scan limit", p, fi.Size(), sweepMaxFileBytes)
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			if !gone(e) {
				s.failScan("read temp %s: %v", p, e)
			}
			return nil
		}
		rel, _ := filepath.Rel(s.tmpDir, p)
		s.scanPersistentBytes("tempfile:"+rel, route, attr, b)
		return nil
	})
	if err != nil {
		s.failScan("walk temp: %v", err)
	}
}

// ---- reporting --------------------------------------------------------------

func (s *sweep) findings() []*sweepHitRec {
	out := make([]*sweepHitRec, 0, len(s.hits))
	for _, h := range s.hits {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (s *sweep) writeFindings(path string) {
	if path == "" {
		return
	}
	b, _ := json.MarshalIndent(map[string]any{
		"seed": s.seed, "requests": s.nreq, "status_histogram": s.statusN,
		"metadata_control_surfaces": keysOf(s.metaSeen), "findings": s.findings(),
	}, "", " ")
	_ = os.WriteFile(path, b, 0o600)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loginDisposable creates a fresh self-service principal for a destructive
// route and returns its bearer token.
func (s *sweep) disposable(i int) (string, bool) {
	name := fmt.Sprintf("sweep-disp-%d-%d", s.seed, i)
	u, err := s.w.c.CreateUser(context.Background(), &core.CreateUserRequest{Username: name, Email: name + "@x.io", Password: apiFuzzPrincipalPassword})
	if err != nil || u == nil {
		return "", false
	}
	sess, _, err := s.w.c.Login(context.Background(), &core.LoginRequest{Username: name, Password: apiFuzzPrincipalPassword})
	if err != nil || sess == nil {
		return "", false
	}
	s.registerRaw("disposable-session", sess.SessionToken)
	return sess.SessionToken, true
}
