// kubernetes.go — the Kubernetes dynamic-secret backend (ADR-035, cloud-IAM): mints a
// short-lived ServiceAccount token via the Kubernetes TokenRequest API
// (POST …/serviceaccounts/{sa}/token). Like AWS STS and GCP these are ephemeral —
// Kubernetes enforces the token's expiry and it cannot be revoked or renewed, so Revoke
// is a no-op and Renew is refused (issue a fresh lease instead).
//
// The encrypted "admin DSN" carries this backend's JSON config:
//
//	{"namespace":"default","service_account":"my-app",
//	 "audiences":["https://my-service"],   // optional; omit for the API-server audience
//	 "api_server":"https://10.0.0.1:443",  // optional; omit to use in-cluster config
//	 "ca_cert":"<PEM>","token":"<bearer>"} // required when api_server is set
//
// namespace + service_account are required. When api_server is omitted the engine uses
// the standard in-cluster configuration (KUBERNETES_SERVICE_HOST/PORT + the mounted
// service-account token and CA) — so no credentials live in Keyorix config when the
// server runs in the cluster. The identity making the call (in-cluster SA or the
// configured token) must hold `create` on the `serviceaccounts/token` subresource for
// the target ServiceAccount. To stay dependency-free (no client-go) the TokenRequest is
// a small REST call over net/http, mirroring the Kubernetes sync agent's REST sink.
package dynamic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// k8sMinExpirationSeconds is the Kubernetes TokenRequest minimum (10 minutes); the
// API server silently bumps anything lower, so we floor it for an honest lease TTL.
const k8sMinExpirationSeconds = 600

const (
	k8sSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known path, not a credential
	k8sSACAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// k8sTokenMinter is the slice of Kubernetes the engine uses — an interface seam so the
// engine is unit-tested with a fake and the REST/TLS plumbing stays contained here.
type k8sTokenMinter interface {
	mintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expiration time.Duration) (token string, expiry time.Time, err error)
}

// KubernetesEngine mints short-lived ServiceAccount tokens via the TokenRequest API.
type KubernetesEngine struct {
	minter k8sTokenMinter // nil uses the real REST minter built from the config
}

func (e *KubernetesEngine) BackendType() string        { return "kubernetes" }
func (e *KubernetesEngine) SupportsNativeExpiry() bool { return true } // Kubernetes enforces the token TTL
func (e *KubernetesEngine) IsEphemeralBackend() bool   { return true }

type k8sConfig struct {
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	Audiences      []string `json:"audiences,omitempty"`
	APIServer      string   `json:"api_server,omitempty"`
	CACert         string   `json:"ca_cert,omitempty"`
	Token          string   `json:"token,omitempty"`
}

// Issue mints a token for the configured ServiceAccount. roleName is a label only —
// there is nothing to drop on revoke. creationTemplate is unused.
func (e *KubernetesEngine) Issue(ctx context.Context, adminDSN, _ string, ttl time.Duration) (Credential, string, error) {
	var cfg k8sConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return Credential{}, "", fmt.Errorf("kubernetes: config must be JSON ({\"namespace\":...,\"service_account\":...}): %w", err)
	}
	if strings.TrimSpace(cfg.Namespace) == "" {
		return Credential{}, "", fmt.Errorf("kubernetes: namespace is required")
	}
	if strings.TrimSpace(cfg.ServiceAccount) == "" {
		return Credential{}, "", fmt.Errorf("kubernetes: service_account is required")
	}

	expiration := ttl
	if expiration < k8sMinExpirationSeconds*time.Second {
		expiration = k8sMinExpirationSeconds * time.Second // K8s rejects/bumps anything lower
	}

	minter := e.minter
	if minter == nil {
		m, err := newRealK8sMinter(cfg)
		if err != nil {
			return Credential{}, "", err
		}
		minter = m
	}
	token, expiry, err := minter.mintToken(ctx, cfg.Namespace, cfg.ServiceAccount, cfg.Audiences, expiration)
	if err != nil {
		return Credential{}, "", fmt.Errorf("kubernetes: request token: %w", err)
	}

	suffix, err := randString(12)
	if err != nil {
		return Credential{}, "", err
	}
	fields := map[string]string{
		"token":           token,
		"namespace":       cfg.Namespace,
		"service_account": cfg.ServiceAccount,
	}
	if !expiry.IsZero() {
		fields["expiration"] = expiry.UTC().Format(time.RFC3339)
	}
	return Credential{Fields: fields}, "keyorix-dyn-" + suffix, nil
}

// Revoke is a no-op: ServiceAccount tokens self-expire and cannot be invalidated early.
func (e *KubernetesEngine) Revoke(_ context.Context, _, _ string) error { return nil }

// Renew is refused: a token's lifetime is fixed at issue. core.RenewLease guards on
// IsEphemeralBackend before reaching here; this is a defensive backstop.
func (e *KubernetesEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return fmt.Errorf("kubernetes: tokens are not renewable; issue a new lease instead")
}

// realK8sMinter calls the TokenRequest API over net/http, authenticating with either an
// explicitly-configured api_server/token/ca or the in-cluster service-account config.
type realK8sMinter struct {
	host  string // e.g. https://10.0.0.1:443
	token string // bearer token for the TokenRequest call
	hc    *http.Client
}

func newRealK8sMinter(cfg k8sConfig) (*realK8sMinter, error) {
	var host, token string
	var caPEM []byte

	if strings.TrimSpace(cfg.APIServer) != "" {
		// Out-of-cluster: everything comes from the config. A CA is required — we never
		// skip TLS verification (an unverified API server could hand back any token).
		host = strings.TrimRight(cfg.APIServer, "/")
		token = strings.TrimSpace(cfg.Token)
		if token == "" {
			return nil, fmt.Errorf("kubernetes: token is required when api_server is set")
		}
		if strings.TrimSpace(cfg.CACert) == "" {
			return nil, fmt.Errorf("kubernetes: ca_cert is required when api_server is set")
		}
		caPEM = []byte(cfg.CACert)
	} else {
		// In-cluster: the standard env + mounted service-account token and CA.
		h, p := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if h == "" || p == "" {
			return nil, fmt.Errorf("kubernetes: not in-cluster and no api_server set (KUBERNETES_SERVICE_HOST/PORT unset)")
		}
		host = "https://" + net.JoinHostPort(h, p)
		tb, err := os.ReadFile(k8sSATokenPath) // #nosec G304 -- well-known in-cluster path
		if err != nil {
			return nil, fmt.Errorf("kubernetes: read in-cluster token: %w", err)
		}
		token = strings.TrimSpace(string(tb))
		caPEM, err = os.ReadFile(k8sSACAPath) // #nosec G304 -- well-known in-cluster path
		if err != nil {
			return nil, fmt.Errorf("kubernetes: read in-cluster CA: %w", err)
		}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("kubernetes: no certificates in ca bundle")
	}
	return &realK8sMinter{
		host:  host,
		token: token,
		hc: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

func (m *realK8sMinter) mintToken(ctx context.Context, namespace, serviceAccount string, audiences []string, expiration time.Duration) (string, time.Time, error) {
	expSeconds := int64(expiration.Seconds())
	reqBody := map[string]interface{}{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]interface{}{
			"expirationSeconds": expSeconds,
		},
	}
	if len(audiences) > 0 {
		reqBody["spec"].(map[string]interface{})["audiences"] = audiences
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal TokenRequest: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s/token",
		m.host, pathSegment(namespace), pathSegment(serviceAccount))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw)) // #nosec G107 -- host is operator-configured/in-cluster
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.hc.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", time.Time{}, fmt.Errorf("not authorized (HTTP %d) — the caller needs create on serviceaccounts/token for %s/%s", resp.StatusCode, namespace, serviceAccount)
	}
	if resp.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("TokenRequest returned HTTP %d", resp.StatusCode)
	}

	var out struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode TokenRequest response: %w", err)
	}
	if out.Status.Token == "" {
		return "", time.Time{}, fmt.Errorf("TokenRequest returned no token")
	}
	var expiry time.Time
	if out.Status.ExpirationTimestamp != "" {
		expiry, _ = time.Parse(time.RFC3339, out.Status.ExpirationTimestamp)
	}
	return out.Status.Token, expiry, nil
}

// pathSegment guards a namespace/service-account name placed into the request path: K8s
// names are DNS labels (lowercase alphanumerics and '-'), so anything else is rejected
// rather than escaped, closing off path traversal in the constructed URL.
func pathSegment(s string) string {
	if s == "" || strings.ContainsAny(s, "/?#%") {
		return "INVALID"
	}
	return s
}
