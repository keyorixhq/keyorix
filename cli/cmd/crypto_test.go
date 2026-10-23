package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cryptoInventoryEnvelope = `{"data":{
 "generated_at":"2026-10-23T12:00:00Z",
 "policy":{"horizon":"2035-01-01T00:00:00Z","migration_years":3,"unbounded_lifetime_years":10},
 "assets":[
  {"id":"tls.http","name":"TLS certificate (http)","class":"tls-certificate","primitive":"signature","algorithm":"ECDSA-P256\u001b[31m","key_size_bits":256,"asymmetric":true,"post_quantum":false,
   "expires_at":"2026-12-31T00:00:00Z","storage":"certificate /etc/k/tls.pem","risk":{"score":60,"level":"medium","quantum_vulnerable":true,"reasons":["x"]}},
  {"id":"dek","name":"Data encryption key (DEK)","class":"dek","primitive":"ae","algorithm":"AES-256-GCM","key_size_bits":256,"asymmetric":false,"post_quantum":false,
   "storage":"file dek.key","risk":{"score":5,"level":"low","quantum_vulnerable":false,"reasons":["y"]}}
 ],
 "summary":{"total":2,"high":0,"medium":1,"low":1,"quantum_vulnerable":1},
 "warnings":["TLS certificate \"grpc\" could not be inspected"],"notes":[]}}`

const cryptoCBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`

func cryptoServer(t *testing.T, gotQuery *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compliance/crypto-inventory" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if gotQuery != nil {
			*gotQuery = r.URL.RawQuery
		}
		if r.URL.Query().Get("format") == "cbom" {
			w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.6")
			_, _ = fmt.Fprint(w, cryptoCBOM)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, cryptoInventoryEnvelope)
	}))
	t.Cleanup(srv.Close)
	setComplianceCreds(t, srv)
	return srv
}

func runCryptoInventory(t *testing.T, format, output string, force bool) (string, error) {
	t.Helper()
	cryptoInventoryFormat, cryptoInventoryOutput, cryptoInventoryForce = format, output, force
	var err error
	out := captureStdout(t, func() { err = cryptoInventoryCmd.RunE(cryptoInventoryCmd, nil) })
	return out, err
}

func TestCryptoInventory_TableFlagsClassicalKeys(t *testing.T) {
	var q string
	cryptoServer(t, &q)
	out, err := runCryptoInventory(t, "table", "", false)
	if err != nil {
		t.Fatalf("crypto inventory: %v", err)
	}
	if !containsAll(out, "tls.http", "AES-256-GCM", "QUANTUM-VULNERABLE", "medium", "low", "2 assets", "1 quantum-vulnerable", "horizon 2035-01-01") {
		t.Fatalf("table output missing fields:\n%s", out)
	}
	if !containsAll(out, "warning", "grpc") {
		t.Fatalf("server warnings must be shown, not dropped:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("server-supplied strings must be sanitised for the terminal: %q", out)
	}
	if strings.Contains(q, "cbom") {
		t.Fatalf("table must not request the CBOM: %q", q)
	}
	// the AES-256 row must not carry the flag
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "AES-256-GCM") && strings.Contains(line, "QUANTUM-VULNERABLE") {
			t.Fatalf("AES-256 row wrongly flagged: %q", line)
		}
	}
}

func TestCryptoInventory_JSONIsTheDataObject(t *testing.T) {
	cryptoServer(t, nil)
	out, err := runCryptoInventory(t, "json", "", false)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Assets  []map[string]any `json:"assets"`
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("stdout must be clean JSON (progress goes to stderr): %v\n%s", err, out)
	}
	if len(d.Assets) != 2 || d.Summary.Total != 2 {
		t.Fatalf("unexpected JSON: %s", out)
	}
}

func TestCryptoInventory_CBOMRequestsAndEmitsDocumentVerbatim(t *testing.T) {
	var q string
	cryptoServer(t, &q)
	out, err := runCryptoInventory(t, "cbom", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if q != "format=cbom" {
		t.Fatalf("query = %q, want format=cbom", q)
	}
	if strings.TrimSpace(out) != cryptoCBOM {
		t.Fatalf("CBOM must be passed through byte-for-byte, got %q", out)
	}
}

func TestCryptoInventory_CBOMOutputFileRefusesOverwriteWithoutForce(t *testing.T) {
	cryptoServer(t, nil)
	path := filepath.Join(t.TempDir(), "cbom.json")
	if _, err := runCryptoInventory(t, "cbom", path, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != cryptoCBOM {
		t.Fatalf("file = %q, %v", b, err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("inventory files must be owner-only, got %v", st.Mode().Perm())
	}
	if _, err := runCryptoInventory(t, "cbom", path, false); err == nil {
		t.Fatal("second write without --force must fail")
	}
	if _, err := runCryptoInventory(t, "cbom", path, true); err != nil {
		t.Fatalf("--force must overwrite: %v", err)
	}
}

func TestCryptoInventory_RejectsBadFormatBeforeAnyRequest(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	setComplianceCreds(t, srv)
	_, err := runCryptoInventory(t, "xml", "", false)
	if err == nil || !strings.Contains(err.Error(), "table, json or cbom") {
		t.Fatalf("want a format error naming the choices, got %v", err)
	}
	if hit {
		t.Fatal("a bad --format must not reach the server")
	}
}

func TestCryptoInventory_OutputOnlyForMachineFormats(t *testing.T) {
	cryptoServer(t, nil)
	_, err := runCryptoInventory(t, "table", filepath.Join(t.TempDir(), "x"), false)
	if err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("--output with the table format must be refused with guidance, got %v", err)
	}
}

func TestCryptoInventory_ForbiddenSaysWhatToDo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"message":"forbidden"}}`)
	}))
	defer srv.Close()
	setComplianceCreds(t, srv)
	_, err := runCryptoInventory(t, "table", "", false)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want a 403 error, got %v", err)
	}
}
