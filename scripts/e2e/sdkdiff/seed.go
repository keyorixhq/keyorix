package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SeedSecret is one synthetic secret created in project "alpha", environment "production".
type SeedSecret struct{ Name, Value string }

// seedSecrets are synthetic names and values chosen to stress SDK encoding,
// matching and JSON decoding. Nothing here is a real credential.
func seedSecrets() []SeedSecret {
	s := []SeedSecret{
		{"db-password", "s3cret-value"},
		{"api key", "value with space"},
		{"naïve-nfc", "nfc"},
		{"naïve-nfc", "nfd"},
		{"q&a=b?c#d/e", "special-name"},
		{"100%25-lit", "percent"},
		{"plus+sign", "plus"},
		{`quote"and\back`, "quote-name"},
		{"emoji-\U0001F600-name", "emoji-name"},
		{"val-unicode", "héllo wörld ✓ 日本語 \U0001F600"},
		{"val-newline", "line1\nline2\r\nline3\ttab"},
		{"val-quotes", `he said "hi" \ back A \/ end`},
		{"val-json", `{"a":[1,2,{"b":"c"}]}`},
		{"val-key-lookalike", `"value":"fake","token":"fake"`},
		{"val-space", " "},
		{"val-long", strings.Repeat("x", 40000)},
		{"val-control", "bell\u0007 esc\u001b del\u007f"},
	}
	for i := 0; i < 30; i++ {
		s = append(s, SeedSecret{fmt.Sprintf("filler-%02d", i), fmt.Sprintf("filler-value-%02d", i)})
	}
	return append(s, SeedSecret{"zz-late", "late-value"})
}

func idOf(m map[string]any) uint {
	for _, k := range []string{"ID", "id"} {
		if f, ok := m[k].(float64); ok {
			return uint(f)
		}
	}
	return 0
}

func strOf(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	return ""
}

// buildSnapshot initialises a fresh server data directory, creates the
// admin user and seeds synthetic projects/secrets. The result is the golden
// snapshot every scenario run starts from.
func buildSnapshot(binary, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := adminCmd(binary, dir, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		return err
	}
	// The throwaway server must not demand MFA enrolment from its synthetic admin
	// (same override scripts/e2e/harness applies for its smoke legs).
	cfg := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(cfg) // #nosec G304 -- tool-owned dir
	if err != nil {
		return err
	}
	const on, off = "\n  require_mfa: true\n", "\n  require_mfa: false\n"
	if !strings.Contains(string(raw), on) {
		return fmt.Errorf("generated config has no require_mfa: true line to override")
	}
	if err := os.WriteFile(cfg, []byte(strings.Replace(string(raw), on, off, 1)), 0o600); err != nil { // #nosec G306,G703 -- tool-owned dir
		return err
	}
	for _, a := range [][]string{{"encryption", "init", "--config", "./keyorix.yaml"}, {"migrate", "--config", "./keyorix.yaml"}} {
		if err := adminCmd(binary, dir, a...); err != nil {
			return err
		}
	}
	in, err := startServer(binary, dir, true)
	if err != nil {
		return err
	}
	defer in.Stop()
	st, m, err := apiCall("POST", in.BaseURL, "/system/init", "", map[string]string{
		"username": adminUser, "email": adminEmail, "password": adminPW, "display_name": adminUser},
		map[string]string{"X-Keyorix-Bootstrap-Token": bootToken})
	if err != nil || st != 200 {
		return fmt.Errorf("system/init: status %d err %v body %v", st, err, m)
	}
	tok, err := login(in.BaseURL)
	if err != nil {
		return err
	}
	type proj struct {
		Name, Desc string
	}
	var firstEnvAlpha uint
	var alphaID, prodEnv uint
	for _, p := range []proj{{"alpha", "synthetic alpha"}, {"gamma 2", "second project"}, {"beta", ""}} {
		st, m, err := apiCall("POST", in.BaseURL, "/api/v1/projects", tok, map[string]string{"name": p.Name, "description": p.Desc})
		if err != nil || st/100 != 2 {
			return fmt.Errorf("create project %q: %d %v %v", p.Name, st, err, m)
		}
		d, _ := m["data"].(map[string]any)
		id := idOf(d)
		if p.Name == "alpha" {
			alphaID = id
		}
	}
	st, m, err = apiCall("GET", in.BaseURL, fmt.Sprintf("/api/v1/projects/%d/environments", alphaID), tok, nil)
	if err != nil || st != 200 {
		return fmt.Errorf("list envs: %d %v %v", st, err, m)
	}
	d, _ := m["data"].(map[string]any)
	envs, _ := d["environments"].([]any)
	for _, e := range envs {
		em, _ := e.(map[string]any)
		if firstEnvAlpha == 0 {
			firstEnvAlpha = idOf(em)
		}
		if strings.EqualFold(strOf(em, "Name", "name"), "production") {
			prodEnv = idOf(em)
		}
	}
	if prodEnv == 0 {
		return fmt.Errorf("no production environment in seeded project: %v", envs)
	}
	for _, s := range seedSecrets() {
		st, m, err := apiCall("POST", in.BaseURL, "/api/v1/secrets", tok, map[string]any{
			"name": s.Name, "value": s.Value, "project_id": alphaID, "environment_id": prodEnv, "type": "password"})
		if err != nil || st/100 != 2 {
			fmt.Fprintf(os.Stderr, "seed: secret %q rejected: %d %v\n", clipStr(s.Name), st, m["error"])
		}
	}
	// manifest: max ids, so volatile (scenario-created) rows can be told from seeded rows
	man := map[string]any{"alpha_project": alphaID, "prod_env": prodEnv}
	_, pm, _ := apiCall("GET", in.BaseURL, "/api/v1/projects", tok, nil)
	pd, _ := pm["data"].(map[string]any)
	var maxP uint
	pl, _ := pd["projects"].([]any)
	for _, p := range pl {
		if pmm, ok := p.(map[string]any); ok && idOf(pmm) > maxP {
			maxP = idOf(pmm)
		}
	}
	man["project_max"] = maxP
	var maxE uint
	_, em, _ := apiCall("GET", in.BaseURL, "/api/v1/environments", tok, nil)
	ed, _ := em["data"].(map[string]any)
	el, _ := ed["environments"].([]any)
	for _, e := range el {
		if emm, ok := e.(map[string]any); ok && idOf(emm) > maxE {
			maxE = idOf(emm)
		}
	}
	man["env_max"] = maxE
	b, _ := json.MarshalIndent(man, "", "  ")
	return os.WriteFile(filepath.Join(dir, "sdkdiff-seed.json"), b, 0o600) // #nosec G306,G703 -- tool-owned dir
}

func clipStr(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
