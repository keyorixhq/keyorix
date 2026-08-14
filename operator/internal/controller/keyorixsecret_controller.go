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
	"errors"
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
	"sigs.k8s.io/controller-runtime/pkg/controller"
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
	// maxConcurrentReconciles bounds how many KeyorixSecret reconciles run in parallel
	// (r143). ctrl.NewControllerManagedBy defaults to exactly 1 with no override — the
	// operator is deployed as a single cluster-wide instance (see cmd/main.go), so that
	// default means ONE shared worker services every KeyorixSecret in every namespace: a
	// single slow or malicious reconcile (a large Data array, or an entry pointed at an
	// allow-listed-but-slow server) stalls the sole worker and starves reconciliation of
	// every other tenant's KeyorixSecret cluster-wide. A small, fixed pool bounds how much
	// one bad reconcile can crowd out — kept low (rather than "unbounded") because higher
	// concurrency multiplies simultaneous outbound calls to the (trusted, but still
	// external) Keyorix server and simultaneous token-Secret reads; nothing else in this
	// module exposes reconciler tuning via a flag (cf. minRefreshInterval above), so this
	// follows the same fixed-constant convention rather than adding a new --flag.
	maxConcurrentReconciles = 5
	// reconcileTimeout bounds the total wall-clock time a single Reconcile call may run,
	// as defense in depth alongside KeyorixSecretSpec.Data's MaxItems=50 cap (r143):
	// buildDesired fetches every Data entry sequentially, each over HTTP with its own 30s
	// timeout (internal/keyorix.Client), so even a MaxItems-bounded array of entries that
	// are each slow-but-within-timeout could otherwise occupy a worker for up to
	// 50*30s=25m. 5 minutes is comfortably above any realistic sync (fetches normally
	// complete in well under a second each) while capping the worst case to a fraction of
	// that 25-minute ceiling.
	reconcileTimeout = 5 * time.Minute
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

// RBAC (#327/#427): `make manifests` generates operator/config/rbac/role.yaml
// from these markers via controller-gen, which fully regenerates that file on
// every run and does not preserve hand-written content in it -- so the
// rationale below lives here, at the actual source of truth, not in the
// generated output where a routine regen would silently discard it (as
// happened once already: an unpinned `make manifests` run stripped this exact
// explanation from role.yaml before anyone had committed it).
//
// This grants a ClusterRole (not a namespaced Role) because by DEFAULT the
// operator is deployed as a single cluster-wide instance that watches
// KeyorixSecret CRs (a namespaced CRD) across every namespace -- with no
// static namespace list configured it genuinely cannot predict ahead of time
// which namespace the next CR (and its TokenSecretRef/target Secret) will
// land in. Kubernetes RBAC also has no way to scope list/watch by
// resourceNames or to a dynamically changing namespace set, so narrowing this
// to per-namespace RoleBindings isn't possible for that deployment model.
//
// Operators who instead run one instance PER namespace (or per bounded tenant
// set) can opt into least-privilege, namespace-scoped RBAC: see the
// watchNamespaces value in deploy/helm/keyorix-operator, which passes the
// corresponding -watch-namespaces flag (operator/cmd/main.go) and swaps this
// same ClusterRole's binding from a cluster-wide ClusterRoleBinding to a
// namespace-scoped RoleBinding per watched namespace -- the ClusterRole
// definition here stays reusable across both modes (ADR-076).
//
// The verbs below are the minimum the reconcile logic actually uses:
// create/update/patch/get/list/watch to materialise and refresh the target
// Secret, and delete for wipeTargetSecret (this file), which removes the
// target Secret once the upstream Keyorix reference is confirmed gone (#428)
// -- no broader verb (e.g. deletecollection) is granted.
//
// What operator/cmd/main.go ALSO does to bound the blast radius of this (in
// the default cluster-wide mode, necessarily cluster-wide) grant: it scopes
// the manager's Secret informer cache to only Secrets carrying the operator's
// managed-by label (see secretCacheOptions in operator/cmd/main.go), so a
// compromised operator process can't trivially dump every cluster Secret
// straight out of its own in-memory cache -- only ones it already owns via
// this same RBAC.
//
// No marker is declared for keyorixsecrets/finalizers: this controller has no
// finalizer logic (garbage collection of the target Secret relies solely on
// the Kubernetes owner-reference GC, not a finalizer), so that grant would be
// unused, excess RBAC.
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=secrets.keyorix.io,resources=keyorixsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile reads the referenced Keyorix values and writes them into the target Secret.
func (r *KeyorixSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Bound total reconcile time (r143): defense in depth alongside spec.data's MaxItems
	// cap, so a pathological case (many entries, each near its individual 30s HTTP
	// timeout) still can't monopolize this reconciler's limited worker pool
	// (maxConcurrentReconciles) indefinitely.
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

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

	secretName := ks.Spec.Target.Name
	if secretName == "" {
		secretName = ks.Name
	}

	// spec.target.name is mutable — if it changed since the last successful sync, the
	// Secret materialised under the OLD name is now orphaned: no later reconcile ever
	// revisits it by name again (Reconcile only ever looks at the CURRENT secretName),
	// so it would otherwise sit in the cluster forever with its last-synced, possibly
	// since-rotated, plaintext value, still owned by this (now-repurposed) CR, mountable
	// by any workload with ordinary Secret-read RBAC in the namespace. Wipe it BEFORE
	// doing anything else this reconcile, using the same ownership-and-label-checked
	// wipeTargetSecret used for the confirmed-gone path below — it's a no-op if nothing
	// exists under the old name, or if this is the CR's first-ever reconcile
	// (LastTargetName is unset).
	//
	// If the wipe itself fails, orphanWipeErr is threaded through to succeed() below:
	// status.LastTargetName is deliberately NOT advanced to the new name in that case,
	// so the next reconcile retries the orphan wipe instead of forgetting about it.
	var orphanWipeErr error
	if ks.Status.LastTargetName != "" && ks.Status.LastTargetName != secretName {
		if wipeErr := r.wipeTargetSecret(ctx, &ks, ks.Status.LastTargetName); wipeErr != nil {
			orphanWipeErr = wipeErr
			logger.Error(wipeErr, "failed to wipe orphaned target Secret after spec.target.name changed",
				"oldTargetName", ks.Status.LastTargetName, "newTargetName", secretName)
		}
	}

	desired, err := r.buildDesired(ctx, &ks)
	if err != nil {
		logger.Error(err, "failed to assemble secret data")
		switch {
		case errors.Is(err, keyorix.ErrSecretGone):
			// The upstream Keyorix server AFFIRMATIVELY reported (404/403) that a
			// referenced secret no longer exists or is no longer accessible — as
			// opposed to a transient failure (network error, timeout, 5xx) where the
			// target Secret must be left untouched. Without this, a revoked/deleted
			// upstream secret leaves the previously synced target Secret sitting in
			// the cluster indefinitely, fully readable by every workload that mounts
			// it, with no indication anything is wrong (#428).
			return r.wipeAndFailGone(ctx, &ks, secretName, "UpstreamSecretGone", err)
		case errors.Is(err, keyorix.ErrUnauthorized):
			// A 401 doesn't confirm the referenced secret itself is gone, but in
			// practice it overwhelmingly means the machine-identity credential was
			// revoked or rotated — an admin deliberately cut this workload's access.
			// That's the same "stop serving the stale value" signal as a confirmed
			// 404/403, so it gets the same wipe treatment, just with a distinct
			// status reason so it's clear from .status which of the two happened.
			return r.wipeAndFailGone(ctx, &ks, secretName, "UpstreamAccessRevoked", err)
		default:
			return r.fail(ctx, &ks, err, orphanWipeErr)
		}
	}

	hash := hashData(r.hashKey, desired)

	if err := r.applySecret(ctx, &ks, secretName, desired); err != nil {
		logger.Error(err, "failed to apply target Secret")
		return r.fail(ctx, &ks, err, orphanWipeErr)
	}

	if err := r.succeed(ctx, &ks, hash, secretName, orphanWipeErr); err != nil {
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
		// Deliberately NOT treated as a wipe-worthy "access confirmed cut" signal (unlike
		// ErrSecretGone/ErrUnauthorized in Reconcile): a missing/unreadable token Secret
		// means the operator couldn't even ASK the Keyorix server whether access is still
		// valid — it could be a typo in tokenSecretRef, an accidental deletion, transient
		// RBAC drift, or a GC race, none of which confirm the upstream secret or grant was
		// actually revoked. Wiping the target Secret on a merely-ambiguous "we don't know"
		// failure would cause an unnecessary outage for every workload depending on it,
		// the same reasoning that already keeps network errors/5xx out of the wipe path.
		return nil, fmt.Errorf("read token secret %s: %w", ref, err)
	}
	// A CRD-write-only principal (the CRD's own documented least-privilege deployment
	// model has no direct core-Secret read/write RBAC) can name ANY pre-existing Secret
	// in the namespace here — the operator resolves it with its own cluster-wide `get
	// secrets` RBAC, not the requester's. validateServer above already stops the token
	// from being shipped to an attacker-controlled destination, but without this gate
	// the operator would still read an arbitrary Secret's bytes and send them as a
	// bearer token to the (now-trusted) Keyorix server — a residual probe/abuse
	// primitive, and exactly the "point at a Secret you don't have RBAC to read" attack
	// the CRD's threat model is meant to exclude. Require the Secret to already carry a
	// label only a principal with real Secret-write RBAC could have set (a CRD-write-only
	// attacker cannot), so an unlabeled pre-existing Secret can never be used as a token
	// source, however it got created.
	if tokenSecret.Labels[tokenSecretLabel] != tokenSecretValue {
		return nil, fmt.Errorf("token secret %s is missing the required label %s=%s (only a Secret explicitly marked as a Keyorix token source may be used as tokenSecretRef)",
			ref, tokenSecretLabel, tokenSecretValue)
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

// adopt or overwrite a Secret it didn't create. Exported so cmd/main.go can scope the
// manager's Secret informer cache to only Secrets carrying this label (see #327): the
// operator is deployed as a single cluster-wide instance, so its RBAC necessarily grants
// Secret access in every namespace, but the informer backing Owns(&corev1.Secret{}) has no
// reason to list/watch/cache Secrets it doesn't manage. Token Secrets and pre-existing
// unmanaged target Secrets never carry this label, so reads of those are excluded from that
// cache (they're read live instead) and remain unaffected.
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "keyorix-operator"
)

// tokenSecretLabel/tokenSecretValue gate which Secrets buildDesired will resolve as a
// TokenSecretRef. Must be set out-of-band (by whoever creates the token Secret — the
// operator never sets it itself, unlike managedByLabel above) before the controller will
// read that Secret's data and use it as a bearer token.
const (
	tokenSecretLabel = "secrets.keyorix.io/token-secret"
	tokenSecretValue = "true"
)

// fail records a SyncError on the Ready condition and requeues with backoff.
// fail records an ordinary sync failure. orphanWipeErr, when non-nil, means
// this SAME reconcile also detected a spec.target.name change and failed to
// wipe the Secret orphaned under the old name (see Reconcile's orphanWipeErr
// doc) — #G54: before this, that failure was silently dropped whenever the
// reconcile ALSO failed later (buildDesired/applySecret), so .status would
// show only the later failure with no indication a stale, possibly
// revoked/rotated Secret is still sitting in the cluster under the old name,
// mountable by any workload with ordinary Secret-read RBAC. Mirrors
// failGone's identical "WipeFailed" reason/message augmentation.
func (r *KeyorixSecretReconciler) fail(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, cause, orphanWipeErr error) (ctrl.Result, error) {
	reason, msg := "SyncError", cause.Error()
	if orphanWipeErr != nil {
		reason += "OrphanWipeFailed"
		msg = fmt.Sprintf("%s — additionally, wiping the Secret orphaned by a spec.target.name change failed, it may still contain stale/rotated data under the old name: %v", cause.Error(), orphanWipeErr)
	}
	r.setReady(ks, metav1.ConditionFalse, reason, msg)
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Return the cause so the controller's rate-limited workqueue backs off.
	return ctrl.Result{}, cause
}

// wipeAndFailGone wipes the target Secret and records the failure on the Ready
// condition via failGone, distinguishing a successful wipe from one that itself failed.
// Before this, a wipeTargetSecret failure was only passed to logger.Error and otherwise
// discarded: the CR's Ready condition would still read as an ordinary confirmed-gone
// sync failure with no indication the stale (possibly revoked/rotated) Secret was NOT
// actually removed — a delete-blocking admission webhook, RBAC drift, or a transient API
// error could leave it silently mounted into every workload that references it, with
// nothing in .status to say so.
func (r *KeyorixSecretReconciler) wipeAndFailGone(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, secretName, reason string, cause error) (ctrl.Result, error) {
	var wipeErr error
	if err := r.wipeTargetSecret(ctx, ks, secretName); err != nil {
		wipeErr = err
		log.FromContext(ctx).Error(err, "failed to wipe target Secret after upstream access was confirmed cut off")
	}
	return r.failGone(ctx, ks, reason, cause, wipeErr)
}

// failGone is fail's counterpart for a confirmed access-cut upstream failure (#428): it
// records a distinct reason ("UpstreamSecretGone" for a confirmed-gone 404/403,
// "UpstreamAccessRevoked" for a 401 — see the ErrSecretGone/ErrUnauthorized handling in
// Reconcile) so the CR's status makes the wipe visible and explicable, rather than
// looking like an ordinary transient sync failure.
//
// wipeErr, when non-nil, means wipeTargetSecret itself failed: the reason gets a
// "WipeFailed" suffix (e.g. "UpstreamSecretGoneWipeFailed") and the message says so
// explicitly, so a reader of .status alone can tell the stale target Secret may still be
// sitting in the cluster with revoked/rotated data, not just that the upstream fetch
// failed.
func (r *KeyorixSecretReconciler) failGone(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, reason string, cause, wipeErr error) (ctrl.Result, error) {
	msg := cause.Error()
	if wipeErr != nil {
		reason += "WipeFailed"
		msg = fmt.Sprintf("%s — additionally, wiping the stale target Secret failed, it may still contain revoked/rotated data: %v", cause.Error(), wipeErr)
	}
	r.setReady(ks, metav1.ConditionFalse, reason, msg)
	if err := r.Status().Update(ctx, ks); err != nil {
		return ctrl.Result{}, err
	}
	// Still return the cause so the workqueue keeps retrying (with backoff): if the
	// secret or access is restored upstream, the next successful reconcile re-syncs it.
	return ctrl.Result{}, cause
}

// wipeTargetSecret deletes the target Secret when the upstream Keyorix reference has
// been confirmed gone (404/403, or the credential itself was rejected with a 401 — see
// the ErrSecretGone/ErrUnauthorized handling in Reconcile) or when a retarget
// (spec.target.name change) has orphaned the Secret previously materialised under an
// old name. Only a Secret this operator actually manages AND that THIS CR controls is
// ever touched. Two
// checks, mirroring applySecret's write-side rigor:
//   - ManagedByLabel: applySecret already refuses to adopt a pre-existing unmanaged
//     Secret sharing the target name, so wiping an unlabeled Secret here too would risk
//     deleting an unrelated workload's own Secret that merely happens to collide on name.
//   - metav1.IsControlledBy(&secret, ks): ks.Spec.Target.Name is attacker-controlled —
//     it comes straight from the caller's OWN CR spec. Without this check, an attacker
//     with only ordinary namespaced KeyorixSecret-create RBAC could set spec.target.name
//     to the name of a Secret already owned by a DIFFERENT, victim CR and spec.data[0].ref
//     to any nonexistent Keyorix ref: their reconcile would hit ErrSecretGone and delete
//     the victim's Secret on every reconcile, despite never owning it — a sustained,
//     cross-tenant availability attack. Checking ownership, not just the shared label,
//     closes it: only the CR that actually owns the Secret (via SetControllerReference in
//     applySecret) may wipe it. A missing target Secret is a no-op.
func (r *KeyorixSecretReconciler) wipeTargetSecret(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, name string) error {
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: ks.Namespace, Name: name}
	if err := r.Get(ctx, key, &secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if secret.Labels[ManagedByLabel] != ManagedByValue {
		return nil
	}
	if !metav1.IsControlledBy(&secret, ks) {
		return nil
	}
	return client.IgnoreNotFound(r.Delete(ctx, &secret))
}

// succeed records Ready=True and the synced fingerprint. targetName is the CURRENT
// target Secret name (secretName in Reconcile); orphanWipeErr, when non-nil, means a
// retarget (spec.target.name change) was detected this reconcile but wiping the
// Secret orphaned under the OLD name failed.
func (r *KeyorixSecretReconciler) succeed(ctx context.Context, ks *secretsv1alpha1.KeyorixSecret, hash, targetName string, orphanWipeErr error) error {
	now := metav1.Now()
	ks.Status.LastSyncTime = &now
	ks.Status.SyncedHash = hash
	ks.Status.ObservedGeneration = ks.Generation
	if orphanWipeErr == nil {
		// The common case (no retarget, or the retarget's orphan wipe succeeded):
		// advance LastTargetName so a later retarget compares against the right name.
		ks.Status.LastTargetName = targetName
		r.setReady(ks, metav1.ConditionTrue, "Synced", "target Secret is up to date")
	} else {
		// The new target Secret synced fine, but the operator failed to wipe the
		// Secret orphaned under the OLD target name. Deliberately leave
		// LastTargetName pointing at the OLD name (NOT targetName) so the next
		// reconcile retries that wipe instead of silently forgetting about it, and
		// surface the failure in the message so it isn't lost the way a
		// log-only wipeErr previously was (mirrors the wipeAndFailGone fix for the
		// ErrSecretGone/ErrUnauthorized path).
		r.setReady(ks, metav1.ConditionTrue, "Synced",
			fmt.Sprintf("target Secret is up to date; WARNING: failed to wipe the orphaned Secret %q left behind by a spec.target.name change, it may still contain stale data: %v",
				ks.Status.LastTargetName, orphanWipeErr))
	}
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
	_, err := r.setupController(mgr)
	return err
}

// setupController is the guts of SetupWithManager, split out so a test can inspect the
// built controller.Controller (e.g. its MaxConcurrentReconciles) without needing to
// duplicate this exact builder chain — SetupWithManager itself just discards the
// returned controller, matching what builder.Builder.Complete does internally.
func (r *KeyorixSecretReconciler) setupController(mgr ctrl.Manager) (controller.Controller, error) {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KeyorixSecret{}).
		Owns(&corev1.Secret{}).
		// See maxConcurrentReconciles (r143): without this, controller-runtime's default
		// of exactly 1 concurrent reconcile means a single shared worker services every
		// KeyorixSecret in every namespace cluster-wide.
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrentReconciles}).
		Build(r)
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
