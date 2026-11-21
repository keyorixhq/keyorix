package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PILOT-BOOTSTRAP-CLI-1: `system init --ca-file x` worked, then its printed next step
// `keyorix login --server ... --username admin` failed with "cannot trust the TLS
// certificate" (exit 6) because the CA was given for one command only. The next-step
// line must carry the --ca-file the reader just used.
func TestSystemInit_NextStepLoginCarriesTheCAFileFlag(t *testing.T) {
	isolateCLI(t)
	resetSystemInitFlags()
	t.Cleanup(resetSystemInitFlags)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"already_initialized":false,"project":"default","environments":["development"],"user":{"id":1,"username":"admin"}}}`)
	}))
	t.Cleanup(srv.Close)
	caPath := filepath.Join(t.TempDir(), "server.crt")
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if _, err := x509.ParseCertificate(srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, crt, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "Correct-Horse-Battery-9!")
	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "bootstrap-tok")

	out, err := runCLI(t, "system", "init", "--server", srv.URL, "--ca-file", caPath)
	if err != nil {
		t.Fatalf("system init --ca-file: %v", err)
	}
	want := "keyorix login --server " + srv.URL + " --username admin --ca-file " + caPath
	if !strings.Contains(out, want) {
		t.Fatalf("next step does not carry the CA file; want %q in:\n%s", want, out)
	}
}
