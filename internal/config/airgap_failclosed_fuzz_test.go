package config

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect/connecttypes"
)

// FuzzAirgapConfigFailClosed fuzzes the air-gap / connector configuration surface
// and asserts the two fail-closed properties ADR-109 / ADR-082 rest on:
//
//  1. Connector validation is COMPLETE for what wireConnect assumes. server/
//     wire_connect.go has two `log.Fatalf("… should have been caught by
//     cfg.Validate()")` branches — an unrecognised connector type (default case)
//     and a gcp-secret-manager connector with an empty project_id. Those are a
//     documented invariant: Validate() must reject every config that would reach
//     them. This target re-derives that exact precondition and asserts
//     validateConnectSection() rejects any fuzzed ConnectConfig that would drive
//     wireConnect into a Fatalf — i.e. it guards the CONDITION wireConnect
//     depends on, not the conclusion (CLAUDE.md "guard the condition").
//
//  2. The air-gap autocert decision is fail-closed and total: for every fuzzed
//     Config and profile bit, validateAutoCertForProfile(c, airgap) errors iff
//     (airgap AND auto_cert) — never fails open (ACME egress in an air-gapped
//     build) and never false-refuses (auto_cert off, or the full profile).
//
//  3. Config.Validate() never panics on a fuzzed Connect section.
//
// Red/green: TestConnectFailClosedRedGreen plants the exact defect this guards
// (a connector validator that skips the gcp project_id check) and shows property
// (1) catches it.
func FuzzAirgapConfigFailClosed(f *testing.F) {
	// Seeds span: valid-ish, unknown type, gcp-without-project, platform-with-project,
	// malformed aws account, plus the known types so the fuzzer can mutate around them.
	f.Add(true, "aws-secrets-manager", "project", "proj", "", "123456789012", true, true)
	f.Add(true, "gcp-secret-manager", "project", "proj", "", "", false, true)
	f.Add(true, "gcp-secret-manager", "platform", "", "gcp-proj", "", true, false)
	f.Add(true, "vault", "platform", "proj", "", "", true, true)
	f.Add(true, "azure-key-vault", "", "", "", "", false, false)
	f.Add(true, "totally-unknown", "project", "proj", "", "", true, true)
	f.Add(false, "aws-secrets-manager", "project", "", "", "bad", false, true)

	f.Fuzz(func(t *testing.T, enabled bool, ctype, scope, project, projectID, accountID string, airgap, autoCert bool) {
		cc := ConnectConfig{
			Enabled: enabled,
			Connectors: []ConnectorConfig{{
				Name:      "fuzz-connector",
				Type:      ctype,
				Scope:     scope,
				Project:   project,
				ProjectID: projectID,
				AccountID: accountID,
			}},
		}
		c := &Config{}
		c.Server.HTTP.Port = "8080"
		c.Storage.Type = "local"
		c.Storage.Database.Path = "./test.db"
		c.Connect = cc
		c.Server.HTTP.TLS.AutoCert = autoCert
		c.Server.HTTP.TLS.Enabled = true
		c.Server.HTTP.TLS.Domains = []string{"keyorix.example.com"}

		// --- Property 1: fail-closed completeness of connector validation. ---
		accepted := validateConnectSection(c) == nil
		wouldFatalf, why := wireConnectWouldFatalf(cc)
		if accepted && wouldFatalf {
			t.Fatalf("FAIL-OPEN: validateConnectSection ACCEPTED a config wireConnect would log.Fatalf on (%s): type=%q scope=%q project=%q projectID=%q",
				why, ctype, scope, project, projectID)
		}

		// --- Property 2: air-gap autocert decision is total and fail-closed. ---
		err := validateAutoCertForProfile(c, airgap)
		wantRefuse := airgap && autoCert
		if wantRefuse && err == nil {
			t.Fatalf("FAIL-OPEN: air-gapped profile accepted auto_cert (would reach an ACME CA)")
		}
		if !wantRefuse && err != nil {
			t.Fatalf("FALSE-REFUSE: airgap=%v auto_cert=%v but validateAutoCertForProfile errored: %v", airgap, autoCert, err)
		}

		// --- Property 3: full Validate() must not panic on this Connect section. ---
		_ = c.Validate()
	})
}

// wireConnectWouldFatalf re-derives the precondition server/wire_connect.go's two
// "should have been caught by cfg.Validate()" log.Fatalf branches depend on. It
// mirrors wireConnect's own gate (disabled or empty -> never wired, so never
// Fatalf) and its dispatch (unknown type -> default Fatalf; gcp with empty
// project_id -> Fatalf). Kept in lockstep with wire_connect.go by
// TestConnectFailClosedRedGreen's green assertions.
func wireConnectWouldFatalf(cc ConnectConfig) (bool, string) {
	if !cc.Enabled || len(cc.Connectors) == 0 {
		return false, ""
	}
	known := make(map[string]bool, len(connecttypes.KnownTypes))
	for _, t := range connecttypes.KnownTypes {
		known[t] = true
	}
	for _, cn := range cc.Connectors {
		if !known[cn.Type] {
			return true, "unrecognized type -> wireConnect default log.Fatalf"
		}
		if cn.Type == "gcp-secret-manager" && cn.ProjectID == "" {
			return true, "gcp-secret-manager empty project_id -> wireConnect log.Fatalf"
		}
	}
	return false, ""
}

// validateConnectSectionBuggy is the planted defect for the red/green proof: it
// drops the gcp project_id check, so it accepts a gcp connector wireConnect would
// then Fatalf on. NOT wired into anything.
func validateConnectSectionBuggy(c *Config) error {
	if err := validateConnectTypes(c.Connect); err != nil {
		return err
	}
	if err := validateConnectScopes(c.Connect); err != nil {
		return err
	}
	// (gcp project_id check intentionally omitted — the bug)
	return validateConnectAWSAccountID(c.Connect)
}

func TestConnectFailClosedRedGreen(t *testing.T) {
	// A gcp connector with a valid scope/project but NO project_id: wireConnect
	// would Fatalf on it, so Validate MUST reject it.
	cc := ConnectConfig{
		Enabled: true,
		Connectors: []ConnectorConfig{{
			Name: "c1", Type: "gcp-secret-manager", Scope: "project", Project: "proj", ProjectID: "",
		}},
	}
	c := &Config{Connect: cc}

	wouldFatalf, _ := wireConnectWouldFatalf(cc)
	if !wouldFatalf {
		t.Fatalf("precondition: this config should be one wireConnect Fatalfs on")
	}
	// RED: the buggy validator accepts it -> fail-open the property would catch.
	if validateConnectSectionBuggy(c) == nil && wouldFatalf {
		// This is the violation the fuzzer asserts against; confirm it is real.
	} else {
		t.Fatalf("red proof broken: buggy validator unexpectedly rejected the gcp-no-project_id config")
	}
	// GREEN: the real validator rejects it.
	if validateConnectSection(c) == nil {
		t.Fatalf("green proof broken: real validateConnectSection ACCEPTED a gcp connector with no project_id")
	}
	// GREEN: a well-formed gcp connector (with project_id) is accepted and does
	// NOT trip the wireConnect precondition (keeps the mirror honest).
	okCC := ConnectConfig{Enabled: true, Connectors: []ConnectorConfig{{
		Name: "c1", Type: "gcp-secret-manager", Scope: "project", Project: "proj", ProjectID: "gcp-proj-123",
	}}}
	okC := &Config{Connect: okCC}
	if validateConnectSection(okC) != nil {
		t.Fatalf("green proof broken: real validator rejected a well-formed gcp connector")
	}
	if f, _ := wireConnectWouldFatalf(okCC); f {
		t.Fatalf("mirror drift: wireConnectWouldFatalf flags a well-formed gcp connector")
	}
}
