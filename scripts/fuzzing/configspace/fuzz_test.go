package configspace

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"

	"github.com/keyorixhq/keyorix/internal/config"
)

const fuzzCanary = "cnryfuzz0123456789ab"

// envCanary is the value the harness puts into the env-sourced secrets
// (KEYORIX_SIEM_TOKEN, KEYORIX_DB_PASSWORD, KEYORIX_SCIM_TOKEN). It differs from
// fuzzCanary so that an error echoing it is always a leak: nothing but a secret
// accessor can bring it into an error text, whatever the document says.
const envCanary = "cnryenv0123456789abcd"

// unknownKeyEcho matches the part of a load error that repeats a key NAME taken from the
// file ("unknown key \"x\" at the top level of the file ..."). Naming the misspelt key is
// the point of that message, so a canary that the fuzzer typed as a key name is not a
// disclosure of a secret value. Values, DSNs, tokens and every other part of the error are
// still checked.
//
// The field branch allows spaces in the key (YAML keys may contain them) but stops at ';'
// and newlines: yaml v4 joins several construct errors with "; ", and a greedy match would
// mask a value echo that sits between two key echoes. A key containing ';' therefore stays
// unmasked, which fails closed. Same pattern as configcompat's keyEcho.
var unknownKeyEcho = regexp.MustCompile(`unknown key "[^"]*"|field [^;\n]+ not found in type [\w.]+`)

// leaksCanary reports whether an error text discloses the canary outside an unknown-key echo.
func leaksCanary(verdict string) bool {
	return leaks(verdict, fuzzCanary)
}

func leaks(verdict, canary string) bool {
	return strings.Contains(unknownKeyEcho.ReplaceAllString(verdict, `-`), canary)
}

// i4Leak is the I4 verdict: does this error text disclose a secret? It fails closed and
// exempts exactly one case, an echo of fuzzCanary that the document placed only under
// non-secret paths of a config that loaded (KFZ-2026-167: Validate echoing an invalid
// storage.type). Everything else that echoes a canary is flagged:
//   - envCanary anywhere outside a key echo (env-sourced secrets never sit in the document);
//   - fuzzCanary in a load error (cfg == nil, loaded false): nothing tells a load error's
//     echo apart from a secret value;
//   - fuzzCanary when any scalar under a secret path of the document holds it, including
//     slice elements such as sso.providers[].client_secret, or when the document does not
//     decode (secretCanaryInDoc fails closed).
//
// It does not see a secret that reaches a non-secret field through ${VAR} expansion of
// server.http.domain/allowed_origins: such an echo carries envCanary and is flagged.
func i4Leak(verdict string, data []byte, loaded bool) bool {
	if leaks(verdict, envCanary) {
		return true
	}
	if !leaks(verdict, fuzzCanary) {
		return false
	}
	return !loaded || secretCanaryInDoc(data)
}

// secretCanaryInDoc reports whether fuzzCanary sits in a scalar value under a secret path
// (IsSecretPath) of any YAML document in data. Sequence elements add "[]" to the path, so
// sso.providers[].client_secret is checked as client_secret. Aliases are resolved by the
// decoder, so an anchor defined under a non-secret key and used under a secret one counts.
// A canary in a map KEY is treated as a key name (as unknownKeyEcho does). It returns true
// when data does not decode, so an input the walk cannot read is flagged rather than exempt.
func secretCanaryInDoc(data []byte) bool {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return true
		}
		if secretCanaryIn("", doc) {
			return true
		}
	}
}

func secretCanaryIn(path string, v any) bool {
	switch n := v.(type) {
	case map[string]any:
		for k, c := range n {
			if secretCanaryIn(joinPath(path, k), c) {
				return true
			}
		}
	case map[any]any:
		for k, c := range n {
			if secretCanaryIn(joinPath(path, fmt.Sprint(k)), c) {
				return true
			}
		}
	case []any:
		for _, c := range n {
			if secretCanaryIn(path+"[]", c) {
				return true
			}
		}
	case nil:
	default:
		return IsSecretPath(path) && strings.Contains(fmt.Sprint(n), fuzzCanary)
	}
	return false
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
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
	// KFZ-2026-167: Validate echoes a canary that sits only in a non-secret enum
	"storage:\n  type: " + fuzzCanary + "\n",
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
				val = envCanary
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
		if i4Leak(v1, data, cfg != nil) {
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
