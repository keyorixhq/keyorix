// Package controller holds the KeyorixSecret reconciler: it reads the referenced
// Keyorix secret values and materialises them into a native Kubernetes Secret, owned by
// the KeyorixSecret so Kubernetes garbage-collects the Secret when the CR is deleted.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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
	conditionReady         = "Ready"
)

// KeyorixSecretReconciler reconciles KeyorixSecret objects.
type KeyorixSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// newClient builds a value fetcher for a server/token; nil uses the real HTTP client.
	// Overridden in tests.
	newClient func(server, token string) valueFetcher
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

	desired, err := r.buildDesired(ctx, &ks)
	if err != nil {
		logger.Error(err, "failed to assemble secret data")
		return r.fail(ctx, &ks, err)
	}

	hash := hashData(desired)
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
	tokenKey := ks.Spec.TokenSecretRef.Key
	if tokenKey == "" {
		tokenKey = "token"
	}
	var tokenSecret corev1.Secret
	ref := types.NamespacedName{Namespace: ks.Namespace, Name: ks.Spec.TokenSecretRef.Name}
	if err := r.Get(ctx, ref, &tokenSecret); err != nil {
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
		if err := controllerutil.SetControllerReference(ks, secret, r.Scheme); err != nil {
			return err
		}
		secret.Type = secretType
		secret.Data = data // operator owns the whole data set; removed keys are pruned
		return nil
	})
	return err
}

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
func (r *KeyorixSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KeyorixSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

// hashData fingerprints the desired data deterministically (sorted keys) so an unchanged
// reconcile produces the same hash.
func hashData(data map[string][]byte) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
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
