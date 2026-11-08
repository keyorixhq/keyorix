package dynamic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// k8sStubEngine returns an engine whose real REST minter talks to a stub API
// server; handler decides every response.
func k8sStubEngine(t *testing.T, handler http.HandlerFunc) *KubernetesEngine {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &KubernetesEngine{minter: &realK8sMinter{
		host:  srv.URL,
		token: "t",
		hc:    &http.Client{Timeout: 5 * time.Second, CheckRedirect: refuseRedirect},
	}}
}

const k8sStubDSN = `{"namespace":"ns","service_account":"sa","revocable":true}`

func tokenReply(expiry string) string {
	return `{"status":{"token":"tok","expirationTimestamp":` + expiry + `}}`
}

func TestK8sIssue_RequiresUsableExpiry(t *testing.T) {
	future := `"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"`
	past := `"` + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `"`
	cases := []struct {
		name    string
		expiry  string
		wantErr bool
	}{
		{"future", future, false},
		{"past", past, true},
		{"empty string", `""`, true},
		{"garbage", `"tomorrow"`, true},
		{"null", `null`, true},
		{"number", `12345`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := k8sStubEngine(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tokenReply(tc.expiry)))
			})
			cred, _, err := e.Issue(context.Background(), `{"namespace":"ns","service_account":"sa"}`, "", time.Hour)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got credential with fields %v", cred.Fields)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cred.Fields["expiration"] == "" {
				t.Fatal("credential has no expiration")
			}
		})
	}
}

func TestK8sIssue_Non2xxIsAnError(t *testing.T) {
	future := `"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"`
	for _, code := range []int{300, 301, 302, 304, 307, 308} {
		e := k8sStubEngine(t, func(w http.ResponseWriter, r *http.Request) {
			// A redirect status without Location: the client hands the response back.
			w.WriteHeader(code)
			_, _ = w.Write([]byte(tokenReply(future)))
		})
		if _, _, err := e.Issue(context.Background(), `{"namespace":"ns","service_account":"sa"}`, "", time.Hour); err == nil {
			t.Errorf("status %d with a valid-looking body was accepted", code)
		}
	}
}

func TestK8sIssue_RevocableBoundSecretNon2xx(t *testing.T) {
	future := `"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"`
	e := k8sStubEngine(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets") && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte(`{"metadata":{"uid":"u"}}`))
			return
		}
		_, _ = w.Write([]byte(tokenReply(future)))
	})
	if _, _, err := e.Issue(context.Background(), k8sStubDSN, "", time.Hour); err == nil {
		t.Fatal("bound Secret creation answered 302 and Issue still succeeded")
	}
}

func TestK8sRevoke_StatusHandling(t *testing.T) {
	cases := []struct {
		code    int
		wantErr bool
	}{
		{200, false}, {202, false}, {204, false}, {404, false},
		{301, true}, {302, true}, {304, true}, {307, true}, {400, true}, {403, true}, {500, true},
	}
	for _, tc := range cases {
		e := k8sStubEngine(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
		})
		err := e.Revoke(context.Background(), k8sStubDSN, "keyorix-dyn-abc")
		if (err != nil) != tc.wantErr {
			t.Errorf("Revoke with status %d: err = %v, wantErr %v", tc.code, err, tc.wantErr)
		}
	}
}
