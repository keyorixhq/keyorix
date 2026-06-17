package k8ssync

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// RESTSink writes Kubernetes Secrets by talking to the Kubernetes API directly over
// HTTPS, using the in-cluster service-account credentials. It deliberately avoids a
// client-go dependency: a Secret get/apply is a small, well-defined REST call, and
// staying dependency-free keeps the agent tiny (mirrors how the Azure rotation
// backend talks to Graph over net/http rather than pulling the SDK). Satisfies Sink.
type RESTSink struct {
	host         string // e.g. https://10.0.0.1:443
	token        string // service-account bearer token
	fieldManager string // Server-Side Apply field manager
	hc           *http.Client
}

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known k8s path, not a credential
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// NewInClusterSink builds a RESTSink from the standard in-cluster environment: the
// API host/port from KUBERNETES_SERVICE_HOST/PORT and the projected service-account
// token + CA bundle. Returns an error when not running inside a cluster.
func NewInClusterSink() (*RESTSink, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in-cluster: KUBERNETES_SERVICE_HOST/PORT unset")
	}
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates in %s", saCAPath)
	}
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return &RESTSink{
		host:         "https://" + net.JoinHostPort(host, port),
		token:        strings.TrimSpace(string(token)),
		fieldManager: "keyorix-sync",
		hc:           hc,
	}, nil
}

// Get returns the decoded data of the named Secret, or (nil, nil) when it does not
// exist.
func (s *RESTSink) Get(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	req, err := s.newRequest(ctx, http.MethodGet, s.secretPath(namespace, name), "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("get secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}

	var body struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	out := make(map[string][]byte, len(body.Data))
	for k, b64 := range body.Data {
		dec, derr := base64.StdEncoding.DecodeString(b64)
		if derr != nil {
			return nil, fmt.Errorf("decode key %q of %s/%s: %w", k, namespace, name, derr)
		}
		out[k] = dec
	}
	return out, nil
}

// Apply create-or-updates the named Secret to hold exactly data, using Server-Side
// Apply (idempotent, no resource-version handshake). The agent owns the data field
// via its field manager, so keys it no longer maps are pruned on the next apply.
func (s *RESTSink) Apply(ctx context.Context, namespace, name string, data map[string][]byte) error {
	encoded := make(map[string]string, len(data))
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	payload := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]string{"name": name, "namespace": namespace},
		"type":       "Opaque",
		"data":       encoded,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal secret %s/%s: %w", namespace, name, err)
	}

	q := url.Values{}
	q.Set("fieldManager", s.fieldManager)
	q.Set("force", "true")
	path := s.secretPath(namespace, name) + "?" + q.Encode()

	// Server-Side Apply: PATCH with the apply content type. JSON is valid YAML, so the
	// apply-patch+yaml media type accepts this body.
	req, err := s.newRequest(ctx, http.MethodPatch, path, "application/apply-patch+yaml", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("apply secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	return nil
}

func (s *RESTSink) secretPath(namespace, name string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", url.PathEscape(namespace), url.PathEscape(name))
}

// newRequest builds an authenticated request; contentType is set when non-empty.
func (s *RESTSink) newRequest(ctx context.Context, method, path, contentType string, body *bytes.Reader) (*http.Request, error) {
	var r *http.Request
	var err error
	if body != nil {
		r, err = http.NewRequestWithContext(ctx, method, s.host+path, body)
	} else {
		r, err = http.NewRequestWithContext(ctx, method, s.host+path, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	r.Header.Set("Authorization", "Bearer "+s.token)
	r.Header.Set("Accept", "application/json")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r, nil
}
