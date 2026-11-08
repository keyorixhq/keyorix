package evidencesink

// webhook_hostile_fuzz_test.go: FuzzWebhookHostileReceiver is the hostile-backend
// record-and-mutate target for the evidence webhook sink (rules: internal/
// fuzzutil/hostile/RULES.md). A webhook receiver only has to acknowledge with a
// 2xx; the interesting properties are therefore bounded retries/redirects, the
// context deadline, no goroutine/FD leak, no cross-host redirect, and that a
// non-2xx final status is never reported as delivered. The bearer token must
// not appear in errors or logs.

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const hostileHookToken = "kx-hostile-webhook-token-91ab"

func FuzzWebhookHostileReceiver(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Status: 10}, {Status: 16}, {Status: 6}, {Redir: 1}, {Redir: 3}, {Redir: 5},
		{Occ: 1, Status: 16}, {Fault: 1}, {Fault: 4}, {Fault: 5},
		{Frame: 1}, {Frame: 11}, {Enc: 2}, {Ops: []hostile.Op{{Code: 4, A: 0, B: 3}}},
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: []hostile.Route{{Name: "hook", Method: "POST", Prefix: "/ev", Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(`{"ok":true}`)}
			}}},
			Program: p, AllowRedirect: true, Retries: true, // same-host redirects are permitted by refuseRedirect
			Credentials: []string{hostileHookToken}, RequestCeiling: maxAttempts,
		})
		defer h.Close()
		w, err := newWebhook(WebhookConfig{
			Endpoint: h.URL() + "/ev", Token: hostileHookToken,
			AllowPrivateNetworkTarget: true, AllowInsecureTransport: true,
		}, time.Millisecond)
		if err != nil {
			t.Fatalf("newWebhook: %v", err)
		}
		ferr := h.Run("Webhook.ForwardEvidence", func(ctx context.Context) error {
			return w.ForwardEvidence(ctx, "pack.json", []byte(`{"evidence":"synthetic"}`), "sig-abc")
		})
		if p.Pristine() && ferr != nil {
			h.Violate("O6 LIVENESS: pristine delivery failed: %v", ferr)
		}
		if ferr == nil {
			recs := h.Served("hook")
			last := served2xx(recs)
			if !last {
				h.Violate("O5/delivered-without-2xx: ForwardEvidence reported delivery but no exchange ended in a 2xx status")
			}
		}
		h.Finish(t.Fatalf)
	})
}

// served2xx reports whether the last non-redirect exchange ended in 2xx.
func served2xx(recs []hostile.Served) bool {
	for _, rec := range slices.Backward(recs) {
		if rec.Redirect != 0 {
			continue
		}
		return rec.Status >= 200 && rec.Status < 300
	}
	return false
}
