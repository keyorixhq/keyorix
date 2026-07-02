// Package controller holds the KeyorixSecret reconciler: it reads the referenced
// Keyorix secret values and materialises them into a native Kubernetes Secret, owned by
// the KeyorixSecret so Kubernetes garbage-collects the Secret when the CR is deleted.
package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

const (
	defaultRefreshInterval = 5 * time.Minute
	// minRefreshInterval floors spec.refreshInterval (#124): with no floor, a CR
	// author (or a compromised CR-writer) could set an absurdly small value (e.g.
	// "1ms") and every successful reconcile would immediately requeue itself —
	// each pass reads the CR, reads the token Secret, calls out to the external
	// Keyorix server, and writes .status — driving a reconcile/API/etcd storm that
	// starves the single shared workqueue for every other KeyorixSecret in the
	// cluster.
	minRefreshInterval = 30 * time.Second
	conditionReady     = "Ready"
)

// KeyorixSecretReconciler reconciles KeyorixSecret objects.
type KeyorixSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// AllowedServers is the set of trusted Keyorix base URLs (scheme://host) the operator
	// will send tokens to. A CR's spec.server MUST match one of these. Without it the
	// operator is a confused deputy: it holds cluster-wide Secret read and would ship a
	// CR-named Secret's value (the "token") to a CR-chosen server — letting a tenant who
	// can only create a CR exfiltrate any namespace Secret to an attacker. Empty = reject
	// every CR (fail closed); configured at startup from --allowed-servers.
	AllowedServers []string
	// newClient builds a value fetcher for a server/token; nil uses the real HTTP client.
	// Overridden in tests.
	newClient func(server, token string) valueFetcher
	// APIReader bypasses the manager's shared cache for reads that must not be
	// cached/watched cluster-wide — the token Secret lookup (#124). It is set from
	// mgr.GetAPIReader() at startup; nil falls back to the cached Client (tests
	// construct a reconciler directly and don't need the distinction).
	APIReader client.Reader
	// hashKey is a random, per-process HMAC key generated once at construction
	// (NewReconciler), used to fingerprint synced values into .status.syncedHash
	// (#124). status is a subresource of the CR, which is very commonly readable
	// by principals who hold no RBAC on the underlying Secret at all — an
	// unsalted, unkeyed sha256 there let any CR-getter run an offline brute-force/
	// dictionary attack against a low-entropy value with zero Secret-read access.
	// The key lives only in memory for this process's lifetime: the hash is a
	// point-in-time fingerprint for drift detection, not something requiring
	// cross-restart stability, so a fresh key on every restart is correct.
	hashKey []byte
}

// NewReconciler builds a KeyorixSecretReconciler with a fresh random HMAC key for
// status.syncedHash (#124). Use this rather than constructing the struct literal
// directly in production code; tests that don't exercise hashData may still build
// the struct literal directly.
func NewReconciler(c client.Client, scheme *runtime.Scheme, apiReader client.Reader, allowedServers []string) (*KeyorixSecretReconciler, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate status-hash HMAC key: %w", err)
	}
	return &KeyorixSecretReconciler{
		Client:         c,
		Scheme:         scheme,
		APIReader:      apiReader,
		AllowedServers: allowedServers,
		hashKey:        key,
	}, nil
}

// validateServer rejects a CR-supplied server that is not https or not in the operator's
// configured allow-list. This is the control that stops the confused-deputy exfiltration:
// the token (a possibly-arbitrary namespace Secret value) only ever travels to a trusted,
// TLS-protected destination the operator was explicitly configured to trust.
func (r *KeyorixSecretReconciler) validateServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL %q", server)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing server %q: only https is allowed (the bearer token must not travel in cleartext)", server)
	}
	if len(r.AllowedServers) == 0 {
		return fmt.Errorf("refusing CR-specified server %q: the operator has no allowed-servers configured and will not send a token to an arbitrary destination — set --allowed-servers to the trusted Keyorix URL(s)", server)
	}
	target := u.Scheme + "://" + u.Host
	for _, a := range r.AllowedServers {
		if au, perr := url.Parse(strings.TrimRight(strings.TrimSpace(a), "/")); perr == nil && au.Scheme+"://"+au.Host == target {
			return nil
		}
	}
	return fmt.Errorf("server %q is not in the operator's allowed-servers list", server)
}

// valueFetcher is the slice of the Keyorix client the reconciler needs (a seam for tests).
type valueFetcher interface {
	FetchValue(ctx context.Context, ref string) ([]byte, error)
}

// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

// Reconcile reads the referenced Keyorix values and writes them into the target Secret.
func (r *KeyorixSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ks secretsv1alpha1.KeyorixSecret
	if err := r.Get(ctx, req.NamespacedName, &ks); err != nil {
		// Deleted: the owned Secret is garbage-collected via its owner reference.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	interval := defaultRefreshInterval
	if ks.Spec.RefreshInterval != nil && ks.Spec.RefreshInterval.Duration > 0 {
		interval = ks.Spec.RefreshInterval.Duration
	}
	if interval < minRefreshInterval {
		interval = minRefreshInterval
	}

	desired, err := r.buildDesired(ctx, &ks)
	if err != nil {
		logger.Error(err, "failed to assemble secret data")
		return r.fail(ctx, &ks, err)
	}

	hash := hashData(r.hashKey, desired)
	secretName := ks.Spec.Target.Name
	if secretName == "" {
		secretName = ks.Name
	}

	if err := r.applySecret(ctx, &ks, secretName, desired); err != nil {
		logger.Error(err, "failed to apply target Secret")
		return r.fail(ctx, &ks, err)
	}

	if err := r.succeed(ctx, &ks, hash); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// buildDesired reads the token and fetches every referenced value, assembling the target
// Secret's data. Any failure fails the whole reconcile so a Secret is never written with
// a partially-fetched set of keys.
func (r *KeyorixSecretReconciler) buildDesired(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret) (map[string][]byte, error) {
	// Validate the destination BEFORE reading the token Secret, so a CR pointing at an
	// untrusted server can't even cause the operator to read (let alone transmit) a Secret.
	if err := r.validateServer(ks.Spec.Server); err != nil {
		return nil, err
	}
	tokenKey := ks.Spec.TokenSecretRef.Key
	if tokenKey == "" {
		tokenKey = "token"
	}
	var tokenSecret corev1.Secret
	ref := types.NamespacedName{Namespace: ks.Namespace, Name: ks.Spec.TokenSecretRef.Name}
	// A direct (uncached) read, not the manager's cached Client (#124): the shared
	// informer cache is scoped to only Secrets this operator manages (see
	// SetupWithManager) so it never pulls arbitrary namespace Secrets — including
	// every token Secret CR authors reference — into the operator's memory. A
	// token Secret is a one-off, per-reconcile lookup; it has no reason to be
	// watched/cached at all.
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	if err := reader.Get(ctx, ref, &tokenSecret); err != nil {
		return nil, fmt.Errorf("read token secret %s: %w", ref, err)
	}
	token := string(tokenSecret.Data[tokenKey])
	if token == "" {
		return nil, fmt.Errorf("token secret %s has no key %q", ref, tokenKey)
	}

	fetcher := r.fetcher(ks.Spec.Server, token)
	desired := make(map[string][]byte, len(ks.Spec.Data))
	for _, d := range ks.Spec.Data {
		val, err := fetcher.FetchValue(ctx, d.Ref)
		if err != nil {
			return nil, fmt.Errorf("fetch %q: %w", d.Ref, err)
		}
		desired[d.SecretKey] = val
	}
	return desired, nil
}

func (r *KeyorixSecretReconciler) fetcher(server, token string) valueFetcher {
	if r.newClient != nil {
		return r.newClient(server, token)
	}
	return keyorix.New(server, token)
}

// applySecret create-or-updates the target Secret with an owner reference to the
// KeyorixSecret, so deleting the CR garbage-collects the Secret.
func (r *KeyorixSecretReconciler) applySecret(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, name string, data map[string][]byte) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ks.Namespace}}
	secretType := ks.Spec.Target.Type
	if secretType == "" {
		secretType = corev1.SecretTypeOpaque
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		// Refuse to adopt-and-overwrite a pre-existing Secret we don't manage. A non-empty
		// ResourceVersion means the object already existed; without a managed-by guard,
		// SetControllerReference would adopt an UNOWNED Secret (e.g. one created manually
		// or by Helm) and replace its data — letting a CR author clobber another workload's
		// same-named Secret. A Secret we created carries the managed-by label and is
		// allowed through.
		if secret.ResourceVersion != "" && secret.Labels[ManagedByLabel] != ManagedByValue {
			return fmt.Errorf("refusing to overwrite existing unmanaged Secret %s/%s", ks.Namespace, name)
		}
		if err := controllerutil.SetControllerReference(ks, secret, r.Scheme); err != nil {
			return err
		}
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		secret.Labels[ManagedByLabel] = ManagedByValue
		secret.Type = secretType
		secret.Data = data // operator owns the whole data set; removed keys are pruned
		return nil
	})
	return err
}

// ManagedByLabel/ManagedByValue mark a Secret as owned by this operator, so it won't
// adopt or overwrite a Secret it didn't create.
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "keyorix-operator"
)

// fail records a SyncError on the Ready condition and requeues with backoff.
func (r *KeyorixSecretReconciler) fail(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause error) (ctrl.Result, error) {
	r.setReady(ks, metav1.ConditionFalse, "SyncError", cause.Error())
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Return the cause so the controller's rate-limited workqueue backs off.
	return ctrl.Result{}, cause
}

// succeed records Ready=True and the synced fingerprint.
func (r *KeyorixSecretReconciler) succeed(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, hash string) error {
	now := metav1.Now()
	ks.Status.LastSyncTime = &now
	ks.Status.SyncedHash = hash
	ks.Status.ObservedGeneration = ks.Generation
	r.setReady(ks, metav1.ConditionTrue, "Synced", "target Secret is up to date")
	return r.Status().Update(ctx, ks)
}

func (r *KeyorixSecretReconciler) setReady(ks *secretsv1alpha1.KeyorixSecret, status metav1.ConditionStatus, reason, msg string) {
	meta := metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ks.Generation,
		LastTransitionTime: metav1.Now(),
	}
	setCondition(&ks.Status.Conditions, meta)
}

// SetupWithManager wires the reconciler to watch KeyorixSecrets and the Secrets it owns.
// The manager's shared cache (wired in cmd/main.go) is label-scoped to only Secrets
// carrying ManagedByLabel=ManagedByValue (#124) — this controller always stamps that
// label on target Secrets it creates (applySecret), so Owns() still fires correctly
// on changes to them, while arbitrary other namespace Secrets (including every token
// Secret CR authors reference) are never pulled into the operator's memory.
func (r *KeyorixSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KeyorixSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// hashData fingerprints the desired data deterministically (sorted keys) so an
// unchanged reconcile produces the same hash. Keyed with an HMAC (#124): the
// fingerprint is persisted into .status.syncedHash, a CR subresource commonly
// readable without any RBAC on the underlying Secret — a plain sha256 there would
// let a CR-getter brute-force a low-entropy value offline with zero Secret-read
// access. key must be non-empty; see NewReconciler.
func hashData(key []byte, data map[string][]byte) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := hmac.New(sha256.New, key)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(data[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// setCondition upserts a condition by type, preserving LastTransitionTime when the status
// is unchanged.
func setCondition(conds *[]metav1.Condition, c metav1.Condition) {
	for i := range *conds {
		if (*conds)[i].Type == c.Type {
			if (*conds)[i].Status == c.Status {
				c.LastTransitionTime = (*conds)[i].LastTransitionTime
			}
			(*conds)[i] = c
			return
		}
	}
	*conds = append(*conds, c)
}
