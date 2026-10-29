package main

// audit_request_id_query_integration_test.go — AUDIT-REQUEST-ID-2 item 1, driven
// against a real server (built binary, SQLite): the request id the server returns in
// X-Request-ID is findable in the audit API.
//
//   - an authenticated mutation (project create) is found by the id of its request
//     through /audit/logs?request_id= and /audit/search?request_id=, and only its rows
//     come back;
//   - the JSON export and export.csv carry the id (a column in the CSV);
//   - the filter is exact: a caller-chosen X-Request-ID is not an id any row carries.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// getRaw is a GET with a bearer token returning status and body.
func getRaw(t *testing.T, target, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// auditRowsByRequestID polls the filtered list until it returns at least one entry
// (audit rows are written asynchronously) and returns the entries under key.
func auditRowsByRequestID(t *testing.T, base, token, path, key, requestID string) []any {
	t.Helper()
	target := base + path + "?request_id=" + url.QueryEscape(requestID)
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body := getRaw(t, target, token)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", target, code, body)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			t.Fatalf("GET %s: %v: %s", target, err, body)
		}
		if rows, ok := dig(parsed, "data", key).([]any); ok && len(rows) > 0 {
			return rows
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestAuditRequestID_QuerySurface_RealServer(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	const (
		masterPass     = "canary-master-passphrase-Q9z-Zq81"
		adminPass      = "Zebra-Quartz-Pelican-Q9z-x7Q41"
		bootstrapToken = "canary-bootstrap-token-Q9z-55aa77"
		clientChosenID = "client-chosen-req-id-001"
	)
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+masterPass)
	for _, step := range []string{"init", "diagnose", "migrate"} {
		args := []string{step, "--config", "./keyorix.yaml"}
		if step == "init" {
			args = []string{"init", "--dev", "--config", "./keyorix.yaml"}
		}
		if out, err := runAdmin(t, bin, dir, env, args...); err != nil {
			t.Fatalf("admin %s failed: %v\n%s", step, err, out)
		}
		if step == "init" {
			injectServerLogFormat(t, filepath.Join(dir, "keyorix.yaml"))
		}
	}

	port := pinFreeHTTPPort(t, dir)
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()    //nolint:errcheck
	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, env...), "KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken, "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://127.0.0.1:" + port
	awaitServerHealthy(t, cmd, logPath, base)

	req, _ := http.NewRequest(http.MethodPost, base+"/system/init", strings.NewReader(fmt.Sprintf(
		`{"username":"reqidadmin","email":"reqid@example.com","password":%q,"display_name":"Req Id"}`, adminPass)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap = %d", resp.StatusCode)
	}

	code, _, login := doJSON(t, http.MethodPost, base+"/auth/login", "", "",
		fmt.Sprintf(`{"username":"reqidadmin","password":%q}`, adminPass))
	token, _ := dig(login, "data", "token").(string)
	if code != http.StatusOK || token == "" {
		t.Fatalf("login = %d", code)
	}

	// An authenticated mutation.
	code, hdr, _ := doJSON(t, http.MethodPost, base+"/api/v1/projects", token, "", `{"name":"reqid-proj","description":"d"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("project create = %d", code)
	}
	mutationID := hdr.Get("X-Request-ID")
	if !serverRequestIDPattern.MatchString(mutationID) {
		t.Fatalf("project create X-Request-ID = %q, want a server-minted id", mutationID)
	}

	for _, tc := range []struct {
		name, path, key, requestID, eventType string
	}{
		{"logs/mutation", "/api/v1/audit/logs", "logs", mutationID, "project."},
		{"search/mutation", "/api/v1/audit/search", "events", mutationID, "project."},
	} {
		rows := auditRowsByRequestID(t, base, token, tc.path, tc.key, tc.requestID)
		if len(rows) == 0 {
			t.Errorf("%s: no audit row for request_id %q", tc.name, tc.requestID)
			continue
		}
		for _, r := range rows {
			m, _ := r.(map[string]any)
			if got, _ := m["request_id"].(string); got != tc.requestID {
				t.Errorf("%s: row %v has request_id %q, want %q (the filter must be exact)", tc.name, m["id"], got, tc.requestID)
			}
		}
		var matched bool
		for _, r := range rows {
			if et, _ := r.(map[string]any)["event_type"].(string); strings.HasPrefix(et, tc.eventType) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s: no row with event_type %q among %v", tc.name, tc.eventType, rows)
		}
	}

	// The caller's own id is not an audit request id: nothing matches it.
	if rows := auditRowsByRequestID(t, base, token, "/api/v1/audit/logs", "logs", clientChosenID); len(rows) != 0 {
		t.Errorf("request_id=%q (client-chosen) matched %d row(s), want none", clientChosenID, len(rows))
	}

	// JSON export carries the id on the mutation's row.
	code, body := getRaw(t, base+"/api/v1/audit/export?limit=1000", token)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	if !strings.Contains(body, `"request_id":"`+mutationID+`"`) {
		t.Errorf("JSON export has no entry with request_id %q: %.400s", mutationID, body)
	}

	// CSV export: a request_id column, filled for the mutation's row.
	code, body = getRaw(t, base+"/api/v1/audit/export.csv", token)
	if code != http.StatusOK {
		t.Fatalf("export.csv = %d: %s", code, body)
	}
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil || len(records) < 2 {
		t.Fatalf("export.csv unparsable (%v): %.400s", err, body)
	}
	col := -1
	for i, h := range records[0] {
		if h == "request_id" {
			col = i
		}
	}
	if col < 0 {
		t.Fatalf("export.csv header has no request_id column: %v", records[0])
	}
	found := false
	for _, rec := range records[1:] {
		if rec[col] == mutationID {
			found = true
		}
	}
	if !found {
		t.Errorf("export.csv has no row with request_id %q", mutationID)
	}
}
