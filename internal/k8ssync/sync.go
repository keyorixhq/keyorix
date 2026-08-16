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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Kubernetes object-name constraints. A namespace is an RFC1123 DNS label; a Secret
// name is an RFC1123 DNS subdomain. Validating these before they reach the API path
// keeps a malformed (or hostile) config mapping from targeting an unintended object.
var (
	dns1123Label     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// k8sSecretKey is the set of characters valid in a Kubernetes Secret data key
	// (validated by the API server as "must be a valid filename": printable ASCII,
	// no path separators — K8SSYNC-001). Without this, a mapping whose Key contains
	// path metacharacters (/, ..) could reach the Kubernetes API with an invalid key
	// name and trigger an opaque server-side rejection rather than a clear local error.
	k8sSecretKey = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

func isDNS1123Label(s string) bool     { return len(s) <= 63 && dns1123Label.MatchString(s) }
func isDNS1123Subdomain(s string) bool { return len(s) <= 253 && dns1123Subdomain.MatchString(s) }
func isK8sSecretKey(s string) bool     { return k8sSecretKey.MatchString(s) }

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
// does not exist. Apply creates or replaces the Secret's data. List returns the names
// of agent-owned Secrets in a namespace (those carrying the managed-by label) and
// Delete removes one — both used only by orphan cleanup.
type Sink interface {
	Get(ctx context.Context, namespace, name string) (map[string][]byte, error)
	Apply(ctx context.Context, namespace, name string, data map[string][]byte) error
	List(ctx context.Context, namespace string) ([]string, error)
	Delete(ctx context.Context, namespace, name string) error
}

// Result summarises one reconcile pass. Created/Updated/Unchanged count target
// Secrets (not individual keys); Failed counts targets skipped due to an error;
// Deleted counts orphaned Secrets reaped by cleanup (or that WOULD be, in dry-run).
// Revoked counts targets whose materialized Secret was removed because the
// upstream value is definitively gone (deleted or access revoked) — #140.
type Result struct {
	Created   int
	Updated   int
	Unchanged int
	Failed    int
	Deleted   int
	Revoked   int
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
// already there. A TRANSIENT fetch or apply failure for one target is recorded and
// skipped — it never aborts the pass or writes a partial Secret — so other targets
// still sync unaffected. A DEFINITIVE per-key failure (ErrUpstreamGone: the upstream
// secret was deleted, or this agent's access to it was revoked) instead drops only
// that one key and applies the Secret with its remaining, still-valid keys — or
// removes the Secret entirely if none are left — so one revoked key in a Secret
// backed by several mappings never collaterally wipes out unrelated live keys
// (G05). See buildDesired for the fetch-time split between the two cases. The
// returned Result tallies the outcome.
func (e *Engine) Reconcile(ctx context.Context, mappings []SecretMapping) (Result, error) { // NOSONAR -- cognitive complexity 31, suppress go:S3776
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
		desired, revokedRefs, ferr := e.buildDesired(ctx, grouped[t])
		if ferr != nil {
			// A TRANSIENT failure (network/5xx — never ErrUpstreamGone, see
			// buildDesired) just skips this pass and retries next time: the value
			// may still be valid, so the existing Secret is left completely
			// untouched rather than written with a key missing or removed outright.
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", t, ferr))
			continue
		}

		if len(revokedRefs) > 0 {
			// #140 / G05: a DEFINITIVE failure for one or more mappings (the
			// upstream secret was deleted, or this agent's access to it was
			// revoked — 404/401/403, never a transient network/5xx error) must
			// propagate to the cluster rather than being left at its last-known,
			// possibly-compromised or now-unauthorized value indefinitely (skip
			// and retry never converges, since the SAME definitive failure
			// recurs every pass). Only the affected key(s) are dropped here —
			// unrelated keys mapped to the same target Secret that fetched fine
			// are still applied below; the Secret itself is removed only if
			// buildDesired left nothing valid for it at all.
			action := "dropping the affected key(s) from the Secret"
			if len(desired) == 0 {
				action = "removing the now-empty Secret entirely"
			}
			res.Errors = append(res.Errors, fmt.Sprintf("%s: upstream secret gone or access revoked for %s; %s", t, strings.Join(revokedRefs, ", "), action))
		}

		if len(desired) == 0 {
			// Every mapping for this target came back revoked/gone: nothing valid
			// remains to materialize, so the stale Secret is removed outright.
			if e.dryRun {
				res.Revoked++
				continue
			}
			if derr := e.sink.Delete(ctx, t.namespace, t.name); derr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: failed to remove revoked secret: %v", t, derr))
				continue
			}
			res.Revoked++
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

		// In dry-run, tally what WOULD change but don't write.
		if e.dryRun {
			if current == nil {
				res.Created++
			} else {
				res.Updated++
			}
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

	// With cleanup enabled, reap Secrets the agent previously created (carrying its
	// managed-by label) whose target is no longer in the config — otherwise a removed
	// mapping leaves a stale Secret behind forever. Runs after the apply loop so the
	// desired set reflects everything this config still wants.
	if e.cleanup {
		e.cleanupOrphans(ctx, grouped, &res)
	}
	return res, nil
}

// managedByLabel marks every Secret the agent owns; cleanup only ever lists and
// deletes Secrets carrying it, so operator- or other-tool-created Secrets are never
// touched. Mirrors the Server-Side Apply field manager (keyorix-sync).
const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "keyorix-sync"
)

// cleanupOrphans lists agent-owned Secrets in every namespace the config still
// references and deletes those whose target is no longer desired. It is scoped to the
// managed-by label (never touches foreign Secrets) and to namespaces present in the
// config — dropping a namespace from the config entirely leaves its Secrets unreaped
// (documented). A target still in the config is kept even if its fetch failed this
// pass, so a transient upstream error can't trigger a delete.
func (e *Engine) cleanupOrphans(ctx context.Context, grouped map[target][]SecretMapping, res *Result) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	desired := make(map[target]bool, len(grouped))
	nsSet := make(map[string]struct{})
	for t := range grouped {
		desired[t] = true
		nsSet[t.namespace] = struct{}{}
	}
	namespaces := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for _, ns := range namespaces {
		owned, err := e.sink.List(ctx, ns)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: list owned: %v", ns, err))
			continue
		}
		sort.Strings(owned) // deterministic order for logs/tests
		for _, name := range owned {
			t := target{namespace: ns, name: name}
			if desired[t] {
				continue
			}
			if e.dryRun {
				res.Deleted++ // report the would-delete without removing anything
				continue
			}
			if derr := e.sink.Delete(ctx, ns, name); derr != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s: delete orphan: %v", t, derr))
				continue
			}
			res.Deleted++
		}
	}
}

// Engine reconciles Keyorix secrets into Kubernetes Secrets via a Fetcher and Sink.
type Engine struct {
	fetcher Fetcher
	sink    Sink
	dryRun  bool
	cleanup bool
}

// Option configures an Engine.
type Option func(*Engine)

// WithDryRun makes the engine compute the diff and report what WOULD change without
// writing any Secret — for config validation and safe previews.
func WithDryRun() Option {
	return func(e *Engine) { e.dryRun = true }
}

// WithCleanup makes the engine reap orphaned Secrets — agent-owned Secrets whose
// target is no longer in the config. Off by default: deleting Secrets is destructive,
// so it must be opted into explicitly. Combines with WithDryRun to preview deletions.
func WithCleanup() Option {
	return func(e *Engine) { e.cleanup = true }
}

// NewEngine constructs an Engine over the given Fetcher and Sink.
func NewEngine(fetcher Fetcher, sink Sink, opts ...Option) *Engine {
	e := &Engine{fetcher: fetcher, sink: sink}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// buildDesired fetches every mapping's referenced value and assembles the target
// Secret's desired data map. The two fetch-error cases are handled differently:
//
//   - ErrUpstreamGone (a DEFINITIVE failure: the referenced Keyorix secret was
//     deleted, or this agent's access was revoked) drops only THAT mapping's key
//     from the desired map and records its ref in the returned revoked slice, then
//     keeps fetching the rest — so one revoked key never discards the other,
//     still-valid keys mapped to the same target Secret.
//   - Any OTHER (transient network/5xx) error aborts the whole build and returns
//     an error: the value may still be valid, so a transient blip must not
//     silently drop — nor overwrite with a partial result — a key from an
//     otherwise-complete Secret. The caller skips this target entirely for the
//     pass in that case.
func (e *Engine) buildDesired(ctx context.Context, mappings []SecretMapping) (desired map[string][]byte, revoked []string, err error) {
	desired = make(map[string][]byte, len(mappings))
	for _, m := range mappings {
		val, ferr := e.fetcher.Fetch(ctx, m.Ref)
		if ferr != nil {
			if errors.Is(ferr, ErrUpstreamGone) {
				revoked = append(revoked, m.Ref)
				continue
			}
			return nil, nil, fmt.Errorf("fetch %q: %w", m.Ref, ferr)
		}
		desired[m.Key] = val
	}
	return desired, revoked, nil
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
	case !isK8sSecretKey(m.Key):
		return fmt.Errorf("key %q is not a valid Kubernetes Secret data key (must match [-._a-zA-Z0-9]+)", m.Key)
	case !isDNS1123Label(m.Namespace):
		return fmt.Errorf("namespace %q is not a valid RFC1123 label", m.Namespace)
	case !isDNS1123Subdomain(m.Name):
		return fmt.Errorf("name %q is not a valid Kubernetes Secret name (RFC1123 subdomain)", m.Name)
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
