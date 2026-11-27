package soak

// workload_test.go: the mixed request driver. The mix is the table soakMix;
// each worker owns a math/rand source seeded from (seed, worker id), so the
// request sequence of a worker is a pure function of the seed. (With more than
// one worker the interleaving across workers is not deterministic; the sequence
// each worker sends is.)
//
// Every kind declares which statuses count as it having done its job
// ("effective"). A run fails when a kind in the mix was never effective: an
// oracle that watched a mix whose requests all bounced off a 401 would be
// green for the wrong reason.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// outcome is what one request did.
type outcome struct {
	Status    int
	Err       error // transport error, timeout or cancel
	Effective bool
}

// kind is one row of the mix.
type kind struct {
	Name   string
	Weight int
	// Covers names the server behaviour the row exercises, for README.md.
	Covers string
	Run    func(w *worker) outcome
}

// failedLoginBudget keeps the failed-login kind inside the server's per-IP
// budget (core.LoginMaxAttempts = 10 failures per 15 minutes): past it every
// login from this address, valid or not, is a 429, and the login/logout kind
// would stop doing its job. 8 leaves two attempts of headroom.
type failedLoginBudget struct {
	mu     sync.Mutex
	start  time.Time
	used   int
	window time.Duration
	max    int
}

func (b *failedLoginBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.start.IsZero() || time.Since(b.start) > b.window {
		b.start, b.used = time.Now(), 0
	}
	if b.used >= b.max {
		return false
	}
	b.used++
	return true
}

type kindStats struct {
	Count, Effective, Errors int64
	Statuses                 map[int]int64
}

// worker is one request loop. Everything it creates is its own (names carry
// the worker id), so workers never collide on a unique name.
type worker struct {
	env    *soakEnv
	id     int
	rng    *rand.Rand
	budget *failedLoginBudget
	ctx    context.Context

	projectID, envID uint
	secrets          []uint
	seq              int

	stats map[string]*kindStats
}

func newWorker(ctx context.Context, env *soakEnv, id int, seed int64, budget *failedLoginBudget) *worker {
	return &worker{
		env: env, id: id, ctx: ctx, budget: budget,
		rng:   rand.New(rand.NewSource(seed*1000 + int64(id))),
		stats: map[string]*kindStats{},
	}
}

// name returns a name unique to this worker for the whole run.
func (w *worker) name(prefix string) string {
	w.seq++
	return fmt.Sprintf("%s-w%d-%d", prefix, w.id, w.seq)
}

// call sends one JSON request with the admin token and reads the body fully.
func (w *worker) call(ctx context.Context, method, path, token string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	return w.callRaw(ctx, method, path, token, "application/json", rd)
}

func (w *worker) callRaw(ctx context.Context, method, path, token, ctype string, body io.Reader) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, w.env.srv.URL+path, body)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := w.env.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

func idOf(body []byte) uint {
	var d struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &d) // case-insensitive: matches "ID" and "id"
	return d.Data.ID
}

func is2xx(s int) bool { return s/100 == 2 }
func is4xx(s int) bool { return s/100 == 4 }

// setup creates the worker's own project and environment.
func (w *worker) setup() error {
	st, b, err := w.call(w.ctx, http.MethodPost, "/api/v1/projects", w.env.adminToken, map[string]any{"name": w.name("soak-project")})
	if err != nil || !is2xx(st) || idOf(b) == 0 {
		return fmt.Errorf("setup project: status=%d err=%v body=%s", st, err, b)
	}
	w.projectID = idOf(b)
	st, b, err = w.call(w.ctx, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments", w.projectID), w.env.adminToken, map[string]any{"name": w.name("soak-env")})
	if err != nil || !is2xx(st) || idOf(b) == 0 {
		return fmt.Errorf("setup environment: status=%d err=%v body=%s", st, err, b)
	}
	w.envID = idOf(b)
	return nil
}

func (w *worker) createSecret() (uint, outcome) {
	st, b, err := w.call(w.ctx, http.MethodPost, "/api/v1/secrets/", w.env.adminToken, map[string]any{
		"name": w.name("soak-secret"), "value": "soak-value-" + fmt.Sprint(w.rng.Int63()),
		"project_id": w.projectID, "environment_id": w.envID, "type": "generic",
	})
	id := uint(0)
	if err == nil && is2xx(st) {
		id = idOf(b)
	}
	return id, outcome{Status: st, Err: err, Effective: id != 0}
}

// pick returns a random existing secret id, or 0.
func (w *worker) pick() (uint, int) {
	if len(w.secrets) == 0 {
		return 0, -1
	}
	i := w.rng.Intn(len(w.secrets))
	return w.secrets[i], i
}

// soakMix is the request mix. Weights are relative. Adding a kind means adding
// a row here and a line to the coverage table in README.md.
var soakMix = []kind{
	{"secret_create", 20, "POST /api/v1/secrets/: encrypt, write version row, audit event", func(w *worker) outcome {
		if len(w.secrets) >= 40 { // keep the live set bounded; deletes are in the mix too
			id, i := w.pick()
			st, _, err := w.call(w.ctx, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), w.env.adminToken, nil)
			w.secrets = append(w.secrets[:i], w.secrets[i+1:]...)
			return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
		}
		id, o := w.createSecret()
		if id != 0 {
			w.secrets = append(w.secrets, id)
		}
		return o
	}},
	{"secret_read", 25, "GET /api/v1/secrets/{id}: authorise, decrypt, last-used bookkeeping, access log", func(w *worker) outcome {
		id, _ := w.pick()
		if id == 0 {
			id, _ = w.createSecret()
			if id != 0 {
				w.secrets = append(w.secrets, id)
			}
		}
		st, _, err := w.call(w.ctx, http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d", id), w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"secret_update", 10, "PUT /api/v1/secrets/{id}: new version row, audit event", func(w *worker) outcome {
		id, _ := w.pick()
		if id == 0 {
			return outcome{Effective: false}
		}
		st, _, err := w.call(w.ctx, http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), w.env.adminToken, map[string]any{"value": "soak-updated-" + fmt.Sprint(w.rng.Int63())})
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"secret_delete", 8, "DELETE /api/v1/secrets/{id}: soft delete, audit event", func(w *worker) outcome {
		id, i := w.pick()
		if id == 0 {
			return outcome{Effective: false}
		}
		st, _, err := w.call(w.ctx, http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), w.env.adminToken, nil)
		w.secrets = append(w.secrets[:i], w.secrets[i+1:]...)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"secret_list", 8, "GET /api/v1/secrets/?project_id=: paginated list, per-row authorisation", func(w *worker) outcome {
		st, _, err := w.call(w.ctx, http.MethodGet, fmt.Sprintf("/api/v1/secrets/?project_id=%d&page_size=20", w.projectID), w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"project_churn", 3, "POST then DELETE /api/v1/projects: project row churn, soft delete", func(w *worker) outcome {
		st, b, err := w.call(w.ctx, http.MethodPost, "/api/v1/projects", w.env.adminToken, map[string]any{"name": w.name("soak-churn-project")})
		if err != nil || !is2xx(st) || idOf(b) == 0 {
			return outcome{Status: st, Err: err}
		}
		st, _, err = w.call(w.ctx, http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d", idOf(b)), w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"environment_churn", 3, "POST then DELETE environments: environment row churn", func(w *worker) outcome {
		st, b, err := w.call(w.ctx, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/environments", w.projectID), w.env.adminToken, map[string]any{"name": w.name("soak-churn-env")})
		if err != nil || !is2xx(st) || idOf(b) == 0 {
			return outcome{Status: st, Err: err}
		}
		st, _, err = w.call(w.ctx, http.MethodDelete, fmt.Sprintf("/api/v1/environments/%d", idOf(b)), w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"audit_read", 5, "GET /api/v1/audit/logs: audit list query", func(w *worker) outcome {
		st, _, err := w.call(w.ctx, http.MethodGet, "/api/v1/audit/logs?page_size=50", w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"login_logout", 1, "POST /auth/login then /auth/logout: bcrypt verify, session create and delete", func(w *worker) outcome {
		st, b, err := w.call(w.ctx, http.MethodPost, "/auth/login", "", map[string]any{"username": soakAdminUser, "password": soakAdminPassword})
		if err != nil || !is2xx(st) {
			return outcome{Status: st, Err: err}
		}
		var d struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &d) != nil || d.Data.Token == "" {
			return outcome{Status: st}
		}
		st, _, err = w.call(w.ctx, http.MethodPost, "/auth/logout", d.Data.Token, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && is2xx(st)}
	}},
	{"failed_login", 2, "POST /auth/login with an unknown user: failed-attempt bookkeeping, 401 then 429 past the budget", func(w *worker) outcome {
		if !w.budget.take() {
			// Budget spent: the kind did its job earlier; do not push the server
			// into refusing the valid logins of this run.
			return outcome{Status: -1, Effective: false}
		}
		st, _, err := w.call(w.ctx, http.MethodPost, "/auth/login", "", map[string]any{"username": w.name("no-such-user"), "password": "wrong-password-1"})
		return outcome{Status: st, Err: err, Effective: err == nil && st == http.StatusUnauthorized}
	}},
	{"bad_bearer", 4, "GET with an invalid and with a missing bearer token: credential lookup miss, 401", func(w *worker) outcome {
		tok := "kx-not-a-token-" + fmt.Sprint(w.rng.Int63())
		if w.rng.Intn(2) == 0 {
			tok = ""
		}
		st, _, err := w.call(w.ctx, http.MethodGet, "/api/v1/secrets/?page_size=5", tok, nil)
		return outcome{Status: st, Err: err, Effective: err == nil && (st == http.StatusUnauthorized || st == http.StatusTooManyRequests)}
	}},
	{"malformed_request", 5, "malformed JSON, wrong content type, unknown route, wrong method, oversize body: 4xx paths", func(w *worker) outcome {
		var st int
		var err error
		switch w.rng.Intn(5) {
		case 0:
			st, _, err = w.callRaw(w.ctx, http.MethodPost, "/api/v1/secrets/", w.env.adminToken, "application/json", strings.NewReader(`{"name": "x", "value": `))
		case 1:
			st, _, err = w.callRaw(w.ctx, http.MethodPost, "/api/v1/secrets/", w.env.adminToken, "text/plain", strings.NewReader("name=x&value=y"))
		case 2:
			st, _, err = w.call(w.ctx, http.MethodGet, "/api/v1/no-such-route/"+fmt.Sprint(w.rng.Intn(100)), w.env.adminToken, nil)
		case 3:
			st, _, err = w.call(w.ctx, http.MethodPatch, "/api/v1/audit/logs", w.env.adminToken, nil)
		default:
			st, _, err = w.callRaw(w.ctx, http.MethodPost, "/api/v1/secrets/", w.env.adminToken, "application/json",
				strings.NewReader(`{"name":"big","value":"`+strings.Repeat("A", 3<<20)+`","project_id":1,"environment_id":1}`))
		}
		return outcome{Status: st, Err: err, Effective: err == nil && is4xx(st)}
	}},
	{"disconnect_cancel", 4, "client cancels the request context 0-3 ms in (audit list): handler sees a dead peer", func(w *worker) outcome {
		ctx, cancel := context.WithCancel(w.ctx)
		time.AfterFunc(time.Duration(w.rng.Intn(3000))*time.Microsecond, cancel)
		st, _, err := w.call(ctx, http.MethodGet, "/api/v1/audit/logs?page_size=100", w.env.adminToken, nil)
		cancel()
		return outcome{Status: st, Err: err, Effective: true} // either result is the point
	}},
	{"disconnect_halfbody", 3, "raw TCP: headers promise a 4096-byte body, 20 bytes arrive, the socket closes", func(w *worker) outcome {
		conn, err := net.DialTimeout("tcp", w.env.srv.Listener.Addr().String(), 2*time.Second)
		if err != nil {
			return outcome{Err: err}
		}
		_, err = fmt.Fprintf(conn, "POST /api/v1/secrets/ HTTP/1.1\r\nHost: soak\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"name\":\"half-body\",",
			w.env.adminToken)
		time.Sleep(time.Duration(w.rng.Intn(3000)) * time.Microsecond)
		_ = conn.Close()
		return outcome{Err: err, Effective: err == nil}
	}},
	{"client_timeout", 3, "client gives up after 1-3 ms (audit list): server finishes work for nobody", func(w *worker) outcome {
		ctx, cancel := context.WithTimeout(w.ctx, time.Duration(1+w.rng.Intn(3))*time.Millisecond)
		defer cancel()
		st, _, err := w.call(ctx, http.MethodGet, "/api/v1/audit/logs?page_size=100", w.env.adminToken, nil)
		return outcome{Status: st, Err: err, Effective: true}
	}},
}

// totalWeight is the sum of the mix weights.
func totalWeight() int {
	n := 0
	for _, k := range soakMix {
		n += k.Weight
	}
	return n
}

// next picks the next kind from the worker's own rng.
func (w *worker) next() *kind {
	r := w.rng.Intn(totalWeight())
	for i := range soakMix {
		if r < soakMix[i].Weight {
			return &soakMix[i]
		}
		r -= soakMix[i].Weight
	}
	return &soakMix[0]
}

// do runs one request of k and records it.
func (w *worker) do(k *kind) {
	o := k.Run(w)
	s := w.stats[k.Name]
	if s == nil {
		s = &kindStats{Statuses: map[int]int64{}}
		w.stats[k.Name] = s
	}
	s.Count++
	s.Statuses[o.Status]++
	if o.Err != nil {
		s.Errors++
	}
	if o.Effective {
		s.Effective++
	}
}

// warmup runs every kind of the mix rounds times in table order, so a lazily
// started worker or cache exists before the baseline is taken.
func (w *worker) warmup(rounds int, total *atomic.Int64) {
	for range rounds {
		for i := range soakMix {
			w.do(&soakMix[i])
			total.Add(1)
		}
	}
}
