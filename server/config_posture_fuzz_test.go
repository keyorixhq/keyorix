// config_posture_fuzz_test.go -- FUZZ-MECH M5: configuration-space fuzzing.
// Fuzzes a small, structured set of independent security-relevant config
// dimensions (not raw YAML bytes -- a byte-level mutation of a whole config
// file mostly produces parse garbage, not the "insecure combination" shape
// this item asks about) through internal/config's own validation
// (config.Config.Validate) and this package's checkTransportTLSPosture --
// both pure functions: no network, no DB, no listener actually opened.
//
// Oracles, all "an accepted/logged-about configuration still enforces the
// documented security property":
//  1. Validate() never accepts server.http.allowed_origins containing "*"
//     (wildcard CORS): validateAllowedOrigins's own documented contract.
//  2. Validate() never accepts a blank/unrecognized storage.type.
//  3. checkTransportTLSPosture never accepts security.require_transport_tls
//     = true alongside an enabled, TLS-disabled listener (the fail-closed
//     half of its own doc comment) -- and when it DOES accept a
//     TLS-disabled listener (require=false), the documented CLEARTEXT
//     warning was actually logged, not silently skipped.
//  4. checkTransportTLSPosture never accepts an unrecognized
//     tls.allowed_ciphers name.
package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// decodeConfigFuzzInput maps 8 fuzzed bytes onto the independent config
// dimensions these oracles care about -- an enum/boolean grid, not a raw
// byte-mutated config file.
type configFuzzDims struct {
	httpEnabled         bool
	tlsEnabled          bool
	requireTransportTLS bool
	wildcardOrigin      bool
	storageType         string
	badCipherName       bool
	trustedProxiesSet   bool
}

var storageTypeChoices = []string{"local", "sqlite", "postgres", "postgresql", "remote", "", "postgress-typo"}

func decodeConfigFuzzInput(data []byte) (configFuzzDims, bool) {
	if len(data) < 7 {
		return configFuzzDims{}, false
	}
	return configFuzzDims{
		httpEnabled:         data[0]&1 == 1,
		tlsEnabled:          data[1]&1 == 1,
		requireTransportTLS: data[2]&1 == 1,
		wildcardOrigin:      data[3]&1 == 1,
		storageType:         storageTypeChoices[int(data[4])%len(storageTypeChoices)],
		badCipherName:       data[5]&1 == 1,
		trustedProxiesSet:   data[6]&1 == 1,
	}, true
}

func buildFuzzedConfig(d configFuzzDims) *config.Config {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = d.httpEnabled
	cfg.Server.HTTP.Port = "8080"
	cfg.Server.HTTP.TLS.Enabled = d.tlsEnabled
	if d.tlsEnabled {
		cfg.Server.HTTP.TLS.CertFile = "cert.pem"
		cfg.Server.HTTP.TLS.KeyFile = "key.pem"
	}
	if d.badCipherName {
		cfg.Server.HTTP.TLS.AllowedCiphers = []string{"TLS_RC4_128_SHA_TOTALLY_MADE_UP"}
	}
	if d.trustedProxiesSet {
		cfg.Server.HTTP.TrustedProxies = []string{"10.0.0.0/8"}
	}
	if d.wildcardOrigin {
		cfg.Server.HTTP.AllowedOrigins = []string{"*"}
	} else {
		cfg.Server.HTTP.AllowedOrigins = []string{"https://app.example.com"}
	}
	cfg.Security.RequireTransportTLS = d.requireTransportTLS
	cfg.Storage.Type = d.storageType
	if d.storageType == "local" || d.storageType == "sqlite" {
		cfg.Storage.Database.Path = "./secrets.db"
	}
	cfg.Locale.Language = "en"
	cfg.Locale.FallbackLanguage = "en"
	return cfg
}

// captureLogs redirects the standard logger for fn's duration and returns
// everything it wrote -- checkTransportTLSPosture's CLEARTEXT warning is a
// log.Printf side effect, not a return value, so this is the only way to
// assert it actually fired.
func captureLogs(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	orig2 := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(orig)
		log.SetFlags(orig2)
	}()
	fn()
	return buf.String()
}

func FuzzConfigSecurityPosture(f *testing.F) {
	f.Add([]byte{1, 0, 1, 0, 0, 0, 0}) // http enabled, TLS off, require=true -> must fail closed
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0}) // http enabled, TLS off, require=false -> must warn
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0}) // http enabled, TLS on -> clean
	f.Add([]byte{1, 0, 0, 1, 0, 0, 0}) // wildcard origin -> Validate must reject
	f.Add([]byte{0, 0, 0, 0, 5, 0, 0}) // storage.type "" -> Validate must reject
	f.Add([]byte{0, 0, 0, 0, 6, 0, 0}) // storage.type typo -> Validate must reject
	f.Add([]byte{1, 1, 0, 0, 0, 1, 0}) // bad cipher name -> must fail closed

	f.Fuzz(func(t *testing.T, data []byte) {
		d, ok := decodeConfigFuzzInput(data)
		if !ok {
			t.Skip("input too short")
		}
		cfg := buildFuzzedConfig(d)

		validateErr := cfg.Validate()

		// Oracle 1: wildcard CORS origin is NEVER accepted.
		if validateErr == nil && d.wildcardOrigin {
			t.Errorf("Validate() accepted a wildcard (\"*\") server.http.allowed_origins entry")
		}

		// Oracle 2: a blank or unrecognized storage.type is NEVER accepted.
		validStorageTypes := map[string]bool{"local": true, "sqlite": true, "postgres": true, "postgresql": true, "remote": true}
		if validateErr == nil && !validStorageTypes[d.storageType] {
			t.Errorf("Validate() accepted storage.type=%q, which is neither blank-tolerant-as-documented nor a recognized type", d.storageType)
		}

		if !d.httpEnabled {
			return // checkTransportTLSPosture is a same-shape check per listener; HTTP is the one this test drives
		}

		var postureErr error
		logged := captureLogs(func() {
			postureErr = checkTransportTLSPosture(cfg)
		})

		// Oracle 4: an unrecognized cipher name is NEVER accepted.
		if d.badCipherName {
			if postureErr == nil {
				t.Errorf("checkTransportTLSPosture accepted an unrecognized tls.allowed_ciphers name")
			}
			return // the cipher check short-circuits before the TLS-posture checks below
		}

		if !d.tlsEnabled {
			// Oracle 3a: require_transport_tls=true + TLS disabled must fail closed, always.
			if d.requireTransportTLS {
				if postureErr == nil {
					t.Errorf("checkTransportTLSPosture accepted an enabled, TLS-disabled HTTP listener with " +
						"security.require_transport_tls=true -- must fail closed")
				}
			} else {
				// Oracle 3b: require_transport_tls=false + TLS disabled must be ACCEPTED
				// (this is a legitimate topology -- TLS terminated by a reverse proxy) but
				// the documented CLEARTEXT warning must actually have been logged, not
				// silently skipped.
				if postureErr != nil {
					t.Errorf("checkTransportTLSPosture unexpectedly refused a TLS-disabled listener with "+
						"require_transport_tls=false: %v", postureErr)
				}
				if !strings.Contains(logged, "CLEARTEXT") {
					t.Errorf("checkTransportTLSPosture accepted a TLS-disabled HTTP listener but did not log "+
						"the documented CLEARTEXT warning (captured log output: %q)", logged)
				}
			}
		}
	})
}
