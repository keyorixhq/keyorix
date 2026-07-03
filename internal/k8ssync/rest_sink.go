package k8ssync

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// errNotManaged is returned by Apply when a pre-existing Secret at the target
// name lacks this agent's managed-by label — the caller should skip/report it,
// not overwrite it.
var errNotManaged = fmt.Errorf("k8ssync: refusing to write: a pre-existing Secret is not managed by this agent")

// ErrNotManaged reports whether err is the "pre-existing unmanaged Secret" refusal
// Apply returns — exported so callers (the sync loop) can distinguish it from a
// transient/network failure and report it distinctly rather than retrying forever.
func ErrNotManaged(err error) bool { return errors.Is(err, errNotManaged) }

// Apply create-or-updates the named Secret to hold exactly data, using Server-Side
// Apply (idempotent, no resource-version handshake). The agent owns the data field
// via its field manager, so keys it no longer maps are pruned on the next apply.
//
// Before writing, it checks whether a Secret ALREADY EXISTS at this name and, if so,
// refuses unless it already carries this agent's managed-by label (#139). force=true
// Server-Side Apply unconditionally takes ownership of every field it sets — including
// on an object created and owned by something else entirely (an operator, a different
// tool) — silently overwriting its data and, because Apply always stamps the
// managed-by label, "branding" it as agent-owned; the next orphan-cleanup pass would
// then DELETE that operator's Secret outright once Keyorix no longer wants it. Only a
// Secret this agent already owns (or one that doesn't exist yet, a fresh create) is
// ever written.
func (s *RESTSink) Apply(ctx context.Context, namespace, name string, data map[string][]byte) error {
	if _, _, exists, owned, err := s.getOwnedMeta(ctx, namespace, name); err != nil {
		return err
	} else if exists && !owned {
		return fmt.Errorf("%s/%s: %w", namespace, name, errNotManaged)
	}

	encoded := make(map[string]string, len(data))
	for k, v := range data {
		encoded[k] = base64.StdEncoding.EncodeToString(v)
	}
	payload := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
			// Stamp ownership so orphan cleanup can find Secrets this agent created
			// (and only those) via a label selector.
			"labels": map[string]string{managedByLabel: managedByValue},
		},
		"type": "Opaque",
		"data": encoded,
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

// List returns the names of agent-owned Secrets in the namespace — those carrying the
// managed-by label. Used by orphan cleanup; the label selector scopes the listing so
// the agent never sees (and so can never delete) Secrets it did not create.
func (s *RESTSink) List(ctx context.Context, namespace string) ([]string, error) {
	q := url.Values{}
	q.Set("labelSelector", managedByLabel+"="+managedByValue)
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets?%s", url.PathEscape(namespace), q.Encode())
	req, err := s.newRequest(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("list secrets in %s: HTTP %d", namespace, resp.StatusCode)
	}
	var body struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode secret list for %s: %w", namespace, err)
	}
	names := make([]string, 0, len(body.Items))
	for _, it := range body.Items {
		names = append(names, it.Metadata.Name)
	}
	return names, nil
}

// Delete removes the named Secret, but only while it still belongs to this agent. It
// re-verifies the managed-by label and pins the exact (uid, resourceVersion) it saw,
// so a Secret that lost the label or was replaced between the orphan listing and here
// is left untouched — closing the list→delete TOCTOU on a destructive action. A 404 is
// success (already gone); a 409 means it changed under us (uid/resourceVersion no
// longer match), so we skip rather than delete a different object.
func (s *RESTSink) Delete(ctx context.Context, namespace, name string) error {
	uid, rv, _, owned, err := s.getOwnedMeta(ctx, namespace, name)
	if err != nil {
		return err
	}
	if !owned {
		return nil // gone, or no longer ours — must not delete
	}
	opts := map[string]interface{}{
		"apiVersion":    "v1",
		"kind":          "DeleteOptions",
		"preconditions": map[string]string{"uid": uid, "resourceVersion": rv},
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		return fmt.Errorf("marshal delete options %s/%s: %w", namespace, name, err)
	}
	req, err := s.newRequest(ctx, http.MethodDelete, s.secretPath(namespace, name), "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	switch {
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusConflict:
		// 404: already gone. 409: the object changed since our owner-check (precondition
		// mismatch) — the Secret we verified is no longer the one on the server, so skip.
		return nil
	case resp.StatusCode >= 400:
		return fmt.Errorf("delete secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	return nil
}

// getOwnedMeta fetches the Secret's uid + resourceVersion and reports whether it
// exists at all, and — when it does — whether it still carries this agent's
// managed-by label. exists=false (owned=false) means absent; exists=true,
// owned=false means a pre-existing Secret this agent does not own.
func (s *RESTSink) getOwnedMeta(ctx context.Context, namespace, name string) (uid, resourceVersion string, exists, owned bool, err error) {
	req, err := s.newRequest(ctx, http.MethodGet, s.secretPath(namespace, name), "", nil)
	if err != nil {
		return "", "", false, false, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return "", "", false, false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusNotFound {
		return "", "", false, false, nil
	}
	if resp.StatusCode >= 400 {
		return "", "", false, false, fmt.Errorf("get secret %s/%s: HTTP %d", namespace, name, resp.StatusCode)
	}
	var body struct {
		Metadata struct {
			UID             string            `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", "", false, false, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	owned = body.Metadata.Labels[managedByLabel] == managedByValue
	return body.Metadata.UID, body.Metadata.ResourceVersion, true, owned, nil
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
