package connect

// vault_hostile_fuzz_test.go: FuzzVaultHostileBackend is the hostile-backend
// record-and-mutate target for the Vault connector (rules: internal/fuzzutil/
// hostile/RULES.md). Unlike FuzzVaultConnectorResponse (one status + one body
// byte string), the mutation program is structure-aware (JSON field ops on any
// of the three Vault routes the connector calls) and adds framing, encoding,
// redirect and network faults, plus goroutine/FD leak and canary oracles.
//
// The strict decoders below are written from Vault's documented wire format
// (KV v1/v2 read, sys/internal/ui/mounts, auth/token/lookup-self), not copied
// from vault.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const hostileVaultToken = "kx-hostile-vault-token-77c1"

func vaultHostileRoutes() []hostile.Route {
	js := func(s string) hostile.Resp {
		return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)}
	}
	return []hostile.Route{
		{Name: "mount", Method: "GET", Prefix: "/v1/sys/internal/ui/mounts/", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"request_id":"r1","data":{"path":"secret/","type":"kv","options":{"version":"2"}}}`)
		}},
		{Name: "secret", Method: "GET", Prefix: "/v1/secret/", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"request_id":"r2","data":{"data":{"password":"s3cr3t"},"metadata":{"version":2,"destroyed":false}}}`)
		}},
		{Name: "lookup", Method: "GET", Prefix: "/v1/auth/token/lookup-self", Valid: func(int, *http.Request) hostile.Resp {
			return js(`{"request_id":"r3","data":{"ttl":3600,"renewable":true,"id":"hidden"}}`)
		}},
	}
}

// strictVaultMountVersion: documented shape data.options.version = "1"|"2";
// a KV v1 mount may report options null. Anything that is not a JSON object
// with an object-or-null data.options is rejected. The "version" member is
// matched exactly (RFC 8259 names are case-sensitive): struct decoding folds
// case, so {"VERSION":"2"} read as v2 while the connector, which looks
// "version" up by its exact name, reads the documented default v1 (input
// 4bbbff823d4680f1; same fix as the Azure decoder in ae8fa1d4c). Not changed
// here: "data" and "options" are still case-folded, as the connector's own
// struct decoding does, so the two agree there and neither follows RFC 8259.
func strictVaultMountVersion(body []byte) (int, bool) {
	var d struct {
		Data *struct {
			Options *map[string]json.RawMessage `json:"options"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &d) != nil || d.Data == nil {
		return 0, false
	}
	if d.Data.Options == nil || *d.Data.Options == nil {
		return 1, true
	}
	raw, ok := (*d.Data.Options)["version"]
	if !ok {
		return 1, true
	}
	var v *string
	if json.Unmarshal(raw, &v) != nil {
		return 0, false
	}
	if v != nil && *v == "2" {
		return 2, true
	}
	return 1, true
}

// strictVaultSecret returns the raw secret payload: a NON-EMPTY JSON object
// (a KV secret is a map of keys to values; Vault refuses to write an empty
// one), nested under data.data for v2 and data for v1.
func strictVaultSecret(body []byte, version int) (string, bool) {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &env) != nil || len(env.Data) == 0 {
		return "", false
	}
	payload := env.Data
	if version == 2 {
		var kv2 struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(env.Data, &kv2) != nil {
			return "", false
		}
		payload = kv2.Data
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(payload, &m) != nil || len(m) == 0 {
		return "", false
	}
	return string(payload), true
}

func FuzzVaultHostileBackend(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Route: 1, Ops: []hostile.Op{{Code: 0, A: 2}}},          // data -> null
		{Route: 0, Ops: []hostile.Op{{Code: 2, A: 4, B: 1}}},    // mount version -> number
		{Route: 1, Frame: 1},                                    // cl-too-long
		{Route: 1, Redir: 3},                                    // same-origin redirect once
		{Route: 1, Fault: 5, Trunc: 3},                          // slow drip, truncated
		{Route: 1, Enc: 2},                                      // gzip bomb
		{Route: 1, Ops: []hostile.Op{{Code: 4, A: 2, B: 3}}},    // huge string
		{Route: 1, Ops: []hostile.Op{{Code: 5, A: 2, B: 3}}},    // deep nesting
		{Route: 1, Ops: []hostile.Op{{Code: 12, A: 4}}},         // canary as secret field
		{Route: 1, Ops: []hostile.Op{{Code: 3, A: 2, B: 0x80}}}, // duplicate key
	} {
		f.Add(hostile.Encode(p))
	}

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: vaultHostileRoutes(), Program: p,
			Credentials: []string{hostileVaultToken}, RequestCeiling: 3,
		})
		defer h.Close()
		c := NewVaultConnector("fuzz", h.URL(), hostileVaultToken, nil)

		var val string
		errGet := h.Run("VaultConnector.GetSecret", func(ctx context.Context) error {
			var e error
			val, e = c.GetSecret(ctx, "secret/data/fuzz")
			return e
		})
		if p.Pristine() && (errGet != nil || val != `{"password":"s3cr3t"}`) {
			h.Violate("O6 LIVENESS: pristine GetSecret returned %q, %v (unmatched: %v)", val, errGet, h.Unmatched())
		}
		if errGet == nil {
			mb, mok := h.Intact("mount")
			sb, sok := h.Intact("secret")
			ver, vok := strictVaultMountVersion(mb)
			want, wok := "", false
			if mok && sok && vok {
				want, wok = strictVaultSecret(sb, ver)
			}
			dup := hostile.HasDuplicateKeys(mb) || hostile.HasDuplicateKeys(sb)
			switch {
			case dup && mok && sok:
				// duplicate member names: no single correct reading (RFC 8259)
			case !mok || !sok:
				h.Violate("O5/incomplete: GetSecret succeeded (%q) although a consumed response was incomplete, redirected or non-200", val)
			case !vok:
				h.Violate("O5/mount: GetSecret succeeded (%q) on a mount-info response the strict decoder rejects", val)
			case !wok:
				h.Violate("O5/empty-or-invalid: GetSecret succeeded with %q (KV v%d) but the strict decoder finds no valid non-empty secret object in the delivered body", val, ver)
			case val != want:
				h.Violate("O5/value: GetSecret returned %q, strict decoder extracts %q", val, want)
			}
		}

		var ttl int
		errTTL := h.Run("VaultConnector.CheckTokenTTL", func(ctx context.Context) error {
			var e error
			ttl, _, e = c.CheckTokenTTL(ctx)
			return e
		})
		if p.Pristine() && (errTTL != nil || ttl != 3600) {
			h.Violate("O6 LIVENESS: pristine CheckTokenTTL returned %d, %v", ttl, errTTL)
		}
		if errTTL == nil {
			lb, ok := h.Intact("lookup")
			var d struct {
				Data *struct {
					TTL       *json.Number `json:"ttl"`
					Renewable *bool        `json:"renewable"`
				} `json:"data"`
			}
			if ok && hostile.HasDuplicateKeys(lb) {
				// ambiguous reading, no assertion
			} else if !ok || json.Unmarshal(lb, &d) != nil || d.Data == nil || d.Data.TTL == nil {
				// A lookup with no explicit ttl is read as ttl=0, i.e. a
				// non-expiring root token (vault.go documents 0 as root).
				h.Violate("O5/ttl: CheckTokenTTL succeeded (ttl=%d) without a delivered, explicit data.ttl", ttl)
			} else if n, err := d.Data.TTL.Int64(); err != nil || int(n) != ttl {
				h.Violate("O5/ttl-value: CheckTokenTTL returned %d, strict decoder %v (%v)", ttl, d.Data.TTL, err)
			}
		}
		h.Finish(t.Fatalf)
	})
}
