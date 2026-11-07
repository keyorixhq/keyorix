package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxRecBody  = 4 << 20
	maxRespKeep = 4096
)

// Proxy is a recording reverse proxy in front of one throwaway server. It
// records every request exactly as the SDK sent it and can replace the
// server's answer with a synthetic fault.
type Proxy struct {
	// Shim adapts server answers to the JSON key style the SDKs were written
	// against (PascalCase ID/Name/...), so deeper SDK behaviour can be compared
	// past the contract break found in raw mode. Off by default.
	Shim bool

	ln  net.Listener
	srv *http.Server
	tr  *http.Transport

	mu       sync.Mutex
	upstream string
	recs     []Rec
	faults   []*Fault
	inflight atomic.Int32 // handlers still running; Drain waits for them (amendment A6)
}

// NewProxy listens on 127.0.0.1 on a free port.
func NewProxy() (*Proxy, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, tr: &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 4}}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// Addr returns host:port.
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Close stops the proxy.
func (p *Proxy) Close() {
	_ = p.srv.Close()
	p.tr.CloseIdleConnections()
}

// SetUpstream points the proxy at a server base URL (http://127.0.0.1:port).
func (p *Proxy) SetUpstream(u string) {
	p.mu.Lock()
	p.upstream = u
	p.mu.Unlock()
}

// SetFault arms a fault for the next Times requests (default 1).
func (p *Proxy) SetFault(f *Fault) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faults = nil
	if f == nil {
		return
	}
	c := *f
	if c.Times <= 0 {
		c.Times = 1
	}
	p.faults = []*Fault{&c}
}

// Drain returns and clears the recorded requests; it also disarms faults.
func (p *Proxy) Drain() []Rec {
	// a request the SDK already gave up on (timeout, aborted big body) can still be in its
	// handler; wait for it so it is attributed to its own step, not to the next scenario
	for i := 0; i < 240 && p.inflight.Load() > 0; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.recs
	p.recs = nil
	p.faults = nil
	return r
}

func (p *Proxy) takeFault() *Fault {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.faults) == 0 {
		return nil
	}
	f := p.faults[0]
	f.Times--
	c := *f
	if f.Times <= 0 {
		p.faults = nil
	}
	return &c
}

func (p *Proxy) push(r Rec) {
	p.mu.Lock()
	p.recs = append(p.recs, r)
	p.mu.Unlock()
}

// ServeHTTP records the request, then applies a fault or forwards it.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.inflight.Add(1)
	defer p.inflight.Add(-1)
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxRecBody+1))
	cut := len(body) > maxRecBody
	if cut {
		body = body[:maxRecBody]
	}
	hdr := map[string][]string{}
	for k, v := range r.Header {
		hdr[k] = append([]string(nil), v...)
	}
	hdr["Host"] = []string{r.Host}
	if len(r.TransferEncoding) > 0 {
		hdr["Transfer-Encoding"] = r.TransferEncoding
	}
	rec := Rec{Method: r.Method, RequestURI: r.RequestURI, Header: hdr, Body: body, BodyCut: cut}

	if strings.HasPrefix(r.RequestURI, "/sink") {
		// redirect target on a different origin (localhost vs 127.0.0.1): records what an SDK
		// forwards after following a cross-origin redirect (oracle X1)
		rec.Faulted = "sink"
		rec.RespStatus = 200
		rec.RespBody = `{"success":true,"data":{}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, rec.RespBody) // #nosec G705 -- fixed JSON literal set two lines above, not request-derived, JSON content type // nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter -- loopback test double writing a fixed JSON literal, no HTML is rendered
		p.push(rec)
		return
	}
	f := p.takeFault()
	if f != nil && f.Kind != "slow" {
		rec.Faulted = f.Kind
		p.synthetic(w, f, &rec)
		p.push(rec)
		return
	}
	if f != nil { // slow: delay, then pass through
		rec.Faulted = "slow"
		select {
		case <-time.After(time.Duration(f.Ms) * time.Millisecond):
		case <-r.Context().Done():
		}
	}
	p.mu.Lock()
	up := p.upstream
	p.mu.Unlock()
	status, rb, err := p.forward(w, r, up, body)
	rec.RespStatus = status
	rec.RespBody = clip(rb)
	if err != nil {
		rec.RespBody = "proxy-error: " + err.Error()
		http.Error(w, "proxy error", http.StatusBadGateway)
		rec.RespStatus = http.StatusBadGateway
	}
	p.push(rec)
}

func clip(b []byte) string {
	if len(b) > maxRespKeep {
		return string(b[:maxRespKeep]) + "...[cut]"
	}
	return string(b)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, up string, body []byte) (int, []byte, error) {
	u, err := url.Parse(up)
	if err != nil {
		return 0, nil, err
	}
	rawPath, rawQuery, _ := strings.Cut(r.RequestURI, "?")
	if p.Shim && r.Method == http.MethodGet && rawPath == "/api/v1/secrets" {
		// contract shim (amendment A1): the request was recorded as the SDK sent it;
		// only the copy sent upstream is adapted so the server can answer it.
		if q, err := url.ParseQuery(rawQuery); err == nil {
			q.Del("environment")
			if q.Get("page_size") == "" {
				q.Set("page_size", "100")
			}
			rawQuery = q.Encode()
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, "http://"+u.Host+"/", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	// Opaque makes Go write the request-target byte for byte as the SDK sent it.
	req.URL = &url.URL{Scheme: "http", Host: u.Host, Opaque: rawPath, RawQuery: rawQuery}
	req.Host = u.Host
	for k, v := range r.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Upgrade", "Content-Length":
			continue
		}
		req.Header[k] = v
	}
	req.ContentLength = int64(len(body))
	resp, err := p.tr.RoundTrip(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if p.Shim && resp.StatusCode/100 == 2 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		rb = shimKeys(rb)
	}
	for k, v := range resp.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length":
			continue
		}
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(rb)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rb) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- loopback test double relaying the upstream test server's bytes verbatim; never rendered as HTML
	return resp.StatusCode, rb, nil
}

var shimRename = map[string]string{"id": "ID", "name": "Name", "type": "Type", "project_id": "ProjectID", "created_at": "CreatedAt", "description": "Description"}

// shimKeys renames the object keys of data.secrets[], data.projects[], data.environments[]
// and of a bare data object (create project) to the PascalCase names the SDKs read.
func shimKeys(body []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if dec.Decode(&doc) != nil {
		return body
	}
	data, ok := doc["data"].(map[string]any)
	if !ok {
		return body
	}
	ren := func(m map[string]any) map[string]any {
		o := make(map[string]any, len(m))
		for k, v := range m {
			if n, ok := shimRename[k]; ok {
				k = n
			}
			o[k] = v
		}
		return o
	}
	for _, key := range []string{"secrets", "projects", "environments"} {
		if arr, ok := data[key].([]any); ok {
			for i, e := range arr {
				if m, ok := e.(map[string]any); ok {
					arr[i] = ren(m)
				}
			}
		}
	}
	if _, ok := data["id"]; ok {
		doc["data"] = ren(data)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

func (p *Proxy) synthetic(w http.ResponseWriter, f *Fault, rec *Rec) {
	send := func(status int, ct, body string) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body) // nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter -- loopback test double replaying a scenario-defined fault body; never rendered as HTML
		rec.RespStatus = status
		rec.RespBody = clip([]byte(body))
	}
	const js = "application/json"
	switch f.Kind {
	case "close":
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				rec.RespStatus = -1
				return
			}
		}
	case "status":
		st := f.Status
		if st == 0 {
			st = 500
		}
		send(st, js, f.Body)
	case "redirect":
		st := f.Status
		if st == 0 {
			st = http.StatusFound
		}
		loc := f.Location
		if loc == "@sink" {
			_, port, _ := net.SplitHostPort(p.Addr())
			loc = "http://localhost:" + port + "/sink"
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(st)
		rec.RespStatus = st
	case "empty200":
		send(200, js, "")
	case "badjson200":
		send(200, js, "{not json")
	case "html200":
		send(200, "text/html", "<html><body>hi</body></html>")
	case "wrongtype200":
		send(200, js, `{"data":{"secrets":"x","projects":"x","environments":"x","value":5,"token":5}}`)
	case "null_data200":
		send(200, js, `{"data":null}`)
	case "nodata200":
		send(200, js, `{}`)
	case "bigbody":
		send(200, js, `{"data":{"secrets":[],"pad":"`+strings.Repeat("A", f.Bytes)+`"}}`)
	default:
		send(500, js, `{"error":"unknown fault"}`)
	}
}
