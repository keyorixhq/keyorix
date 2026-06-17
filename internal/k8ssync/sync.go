// Package k8ssync holds the reconciliation engine for the Keyorix Kubernetes sync
// agent: it materialises selected Keyorix secrets into Kubernetes Secrets and keeps
// them current as the upstream values rotate.
//
// The engine is deliberately decoupled from both Keyorix and Kubernetes via the
// Fetcher and Sink interfaces, so the diff/apply logic is pure and unit-testable;
// later changes wire the real Keyorix API client (Fetcher) and a client-go-backed
// Sink. Values are held only as long as a reconcile pass needs them and are never
// logged.
package k8ssync

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
)

// SecretMapping maps one Keyorix secret reference to a key inside a target
// Kubernetes Secret. Several mappings may target the same Secret with different keys.
type SecretMapping struct {
	Ref       string `yaml:"ref"`       // Keyorix secret reference, e.g. "production/db-password"
	Namespace string `yaml:"namespace"` // target Kubernetes namespace
	Name      string `yaml:"name"`      // target Kubernetes Secret name
	Key       string `yaml:"key"`       // key within the Secret's data map
}

// Fetcher retrieves a secret value by reference from Keyorix.
type Fetcher interface {
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

// Sink reads and writes Kubernetes Secrets. Get returns (nil, nil) when the Secret
// does not exist. Apply creates or replaces the Secret's data.
type Sink interface {
	Get(ctx context.Context, namespace, name string) (map[string][]byte, error)
	Apply(ctx context.Context, namespace, name string, data map[string][]byte) error
}

// Result summarises one reconcile pass. Created/Updated/Unchanged count target
// Secrets (not individual keys); Failed counts targets skipped due to an error.
type Result struct {
	Created   int
	Updated   int
	Unchanged int
	Failed    int
	Errors    []string
}

// target is the (namespace, name) identity of a Kubernetes Secret.
type target struct {
	namespace string
	name      string
}

func (t target) String() string { return t.namespace + "/" + t.name }

// Reconcile groups the mappings by target Secret, fetches each referenced value,
// and creates/updates the Secret only when its desired data differs from what's
// already there. A fetch or apply failure for one target is recorded and skipped —
// it never aborts the pass or writes a partial Secret — so other targets still sync.
// The returned Result tallies the outcome.
func (e *Engine) Reconcile(ctx context.Context, mappings []SecretMapping) (Result, error) {
	var res Result

	grouped, errs := groupByTarget(mappings)
	res.Errors = append(res.Errors, errs...)
	res.Failed += len(errs)

	// Stable order so logs and tests are deterministic.
	targets := make([]target, 0, len(grouped))
	for t := range grouped {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].String() < targets[j].String() })

	for _, t := range targets {
		desired, ferr := e.buildDesired(ctx, grouped[t])
		if ferr != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", t, ferr))
			continue
		}

		current, gerr := e.sink.Get(ctx, t.namespace, t.name)
		if gerr != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: read: %v", t, gerr))
			continue
		}

		if dataEqual(current, desired) {
			res.Unchanged++
			continue
		}

		if aerr := e.sink.Apply(ctx, t.namespace, t.name, desired); aerr != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: apply: %v", t, aerr))
			continue
		}
		if current == nil {
			res.Created++
		} else {
			res.Updated++
		}
	}
	return res, nil
}

// Engine reconciles Keyorix secrets into Kubernetes Secrets via a Fetcher and Sink.
type Engine struct {
	fetcher Fetcher
	sink    Sink
}

// NewEngine constructs an Engine over the given Fetcher and Sink.
func NewEngine(fetcher Fetcher, sink Sink) *Engine {
	return &Engine{fetcher: fetcher, sink: sink}
}

// buildDesired fetches every mapping's referenced value and assembles the target
// Secret's desired data map. Any fetch error fails the whole target (so a transient
// failure can't silently drop a key from an otherwise-complete Secret).
func (e *Engine) buildDesired(ctx context.Context, mappings []SecretMapping) (map[string][]byte, error) {
	desired := make(map[string][]byte, len(mappings))
	for _, m := range mappings {
		val, err := e.fetcher.Fetch(ctx, m.Ref)
		if err != nil {
			return nil, fmt.Errorf("fetch %q: %w", m.Ref, err)
		}
		desired[m.Key] = val
	}
	return desired, nil
}

// groupByTarget buckets mappings by their target Secret, validating each and
// rejecting duplicate keys within one target. Invalid mappings are returned as error
// strings (and excluded) rather than aborting the whole set.
func groupByTarget(mappings []SecretMapping) (map[target][]SecretMapping, []string) {
	grouped := make(map[target][]SecretMapping)
	seen := make(map[string]bool) // "ns/name/key" → already mapped
	var errs []string
	for i, m := range mappings {
		if err := validateMapping(m); err != nil {
			errs = append(errs, fmt.Sprintf("mapping %d: %v", i, err))
			continue
		}
		t := target{namespace: m.Namespace, name: m.Name}
		dk := t.String() + "/" + m.Key
		if seen[dk] {
			errs = append(errs, fmt.Sprintf("mapping %d: duplicate key %q for Secret %s", i, m.Key, t))
			continue
		}
		seen[dk] = true
		grouped[t] = append(grouped[t], m)
	}
	return grouped, errs
}

// validateMapping rejects a mapping missing any required field.
func validateMapping(m SecretMapping) error {
	switch {
	case strings.TrimSpace(m.Ref) == "":
		return fmt.Errorf("ref is required")
	case strings.TrimSpace(m.Namespace) == "":
		return fmt.Errorf("namespace is required")
	case strings.TrimSpace(m.Name) == "":
		return fmt.Errorf("name is required")
	case strings.TrimSpace(m.Key) == "":
		return fmt.Errorf("key is required")
	}
	return nil
}

// dataEqual reports whether two Secret data maps hold exactly the same keys and bytes.
func dataEqual(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !bytes.Equal(av, bv) {
			return false
		}
	}
	return true
}
