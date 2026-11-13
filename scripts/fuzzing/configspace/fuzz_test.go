package configspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

const fuzzCanary = "cnryfuzz0123456789ab"

// unknownKeyEcho matches the part of a load error that repeats a key NAME taken from the
// file ("unknown key \"x\" at the top level of the file ..."). Naming the misspelt key is
// the point of that message, so a canary that the fuzzer typed as a key name is not a
// disclosure of a secret value. Values, DSNs, tokens and every other part of the error are
// still checked.
var unknownKeyEcho = regexp.MustCompile(`unknown key "[^"]*"`)

// leaksCanary reports whether an error text discloses the canary outside an unknown-key echo.
func leaksCanary(verdict string) bool {
	return strings.Contains(unknownKeyEcho.ReplaceAllString(verdict, `unknown key "-"`), fuzzCanary)
}

var fuzzSeeds = []string{
	"",
	// a canary typed as a top-level key name: the error repeats the key (by design) and must not trip I4
	fuzzCanary + ": 1\n",
	"server:\n  http:\n    enabled: true\n    port: \"8080\"\nstorage:\n  type: sqlite\n  database:\n    path: keyorix.db\n",
	"server:\n  http:\n    enabled: true\n    host: 0.0.0.0\n    port: \"8080\"\n    tls:\n      enabled: true\n      cert_file: c.crt\n      key_file: c.key\n      allowed_ciphers: [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]\n    tls_mode: strict\n    metrics_token: " + fuzzCanary + "\n    allowed_origins: [\"https://a.example.com\"]\n    trusted_proxies: [\"10.0.0.0/8\"]\nsecurity:\n  require_transport_tls: true\n  require_mfa: true\n  login_lockout:\n    window: 15m\n    max_attempts: 5\nsession:\n  access_ttl: 30m\n  absolute_ttl: 12h\nstorage:\n  type: sqlite\n  database:\n    path: keyorix.db\n    audit_durability: strict\n  encryption:\n    enabled: true\n    key_provider:\n      type: password\n",
	"storage:\n  type: postgres\n  database:\n    dsn: \"postgres://k:" + fuzzCanary + "@db.example.com:5432/k?sslmode=verify-full\"\n    ssl_mode: require\n    pooler: pgbouncer-session\n",
	"audit:\n  siem:\n    enabled: true\n    provider: splunk\n    endpoint: http://siem.example.com/x\n    token: " + fuzzCanary + "\n    allow_insecure_transport: true\nsecurity:\n  login_lockout:\n    disabled: true\n  recover_admin:\n    keyless_mode: true\nscim:\n  enabled: true\n  token: " + fuzzCanary + "\n",
	"sso:\n  enabled: true\n  providers:\n    - name: okta\n      type: oidc\n      issuer: https://idp.example.com\n      client_id: a\n      client_secret: " + fuzzCanary + "\n      redirect_url: https://k.example.com/auth/sso/okta/callback\n      trust_asserted_email: true\n",
	"storage: {type: remote}\nserver: {grpc: {enabled: true, port: \"9090\", tls: {auto_cert: true}}}\n",
	"environment: development\nserver: {http: {enabled: true, port: \"0\", domain: \"${KEYORIX_CS_UNSET:-x.example.com}\", allowed_origins: [\"${KEYORIX_CS_UNSET}\"]}}\n",
}

// FuzzConfigLoadValidate drives config.Load and Config.Validate with arbitrary YAML and a
// few secret-source environment toggles. It checks I1 (no panic in parse, validate, or
// the derived accessors that boot reads), I4 (a canary secret never appears in an error
// string), determinism of the verdict, and that an accepted configuration survives a
// Save/Load round trip.
func FuzzConfigLoadValidate(f *testing.F) {
	for _, s := range fuzzSeeds {
		for _, env := range []uint8{0, 1, 5, 31} {
			f.Add([]byte(s), env)
		}
	}
	dir, err := os.MkdirTemp("", "configspace-fuzz-")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = os.RemoveAll(dir) })
	tok := filepath.Join(dir, "tok")
	_ = os.WriteFile(tok, []byte("fixture-token-value-0123456789\n"), 0o600)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	rtPath := filepath.Join(dir, "roundtrip.yaml")
	m, merr := LoadModel()
	if merr != nil {
		f.Fatal(merr)
	}

	f.Fuzz(func(t *testing.T, data []byte, envBits uint8) {
		if len(data) > 1<<16 {
			t.Skip()
		}
		// ${VAR} expansion reads the process environment; keep it deterministic
		_ = os.Unsetenv("KEYORIX_CS_UNSET")
		for i, name := range []string{"KEYORIX_SIEM_TOKEN", "KEYORIX_DB_PASSWORD", "KEYORIX_SCIM_TOKEN", "KEYORIX_SIEM_TOKEN_FILE", "KEYORIX_DB_PASSWORD_FILE"} {
			val := ""
			switch {
			case envBits&(1<<i) == 0:
			case strings.HasSuffix(name, "_FILE") && i == 3:
				val = tok
			case strings.HasSuffix(name, "_FILE"):
				val = filepath.Join(dir, "missing")
			default:
				val = fuzzCanary
			}
			if val == "" {
				t.Setenv(name, "")
				_ = os.Unsetenv(name)
			} else {
				t.Setenv(name, val)
			}
		}
		if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		load := func() (verdict string, cfg *config.Config) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic in Load/Validate: %v", r)
				}
			}()
			c, err := config.Load(cfgPath)
			if err != nil {
				return "load: " + err.Error(), nil
			}
			if c.Storage.Type == "" {
				c.Storage.Type = "local"
			}
			if err := c.Validate(); err != nil {
				return "validate: " + err.Error(), c
			}
			return "", c
		}
		v1, cfg := load()
		if leaksCanary(v1) {
			t.Fatalf("secret value in error text: %s", v1)
		}
		if v2, _ := load(); v2 != v1 {
			t.Fatalf("non-deterministic verdict: %q vs %q", v1, v2)
		}
		if v1 != "" || cfg == nil {
			return
		}
		// accepted: everything boot derives from the config must not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic in derived accessors: %v", r)
				}
			}()
			m.PostureHolds(cfg)
			registryInEffect(cfg)
			_ = cfg.Server.HTTP.ListenAddr()
			_ = cfg.Server.GRPC.ListenAddr()
			_, _ = cfg.Server.HTTP.ResolveMetricsToken()
			_ = cfg.Storage.Database.EffectiveAuditDurability(cfg.Storage.Type)
			_ = cfg.Session.GetAccessTTL()
			_ = cfg.Session.GetAbsoluteTTL()
			_ = cfg.SecretFilePaths()
		}()
		if err := config.Save(rtPath, cfg); err == nil {
			c2, err := config.Load(rtPath)
			if err != nil {
				t.Fatalf("accepted configuration does not reload after Save: %v", err)
			}
			if c2.Storage.Type == "" {
				c2.Storage.Type = "local"
			}
			if err := c2.Validate(); err != nil {
				t.Fatalf("accepted configuration is refused after Save and Load: %v", err)
			}
		}
	})
}
