package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

// fakeFetcher serves values from a map. Refs in failRefs error with a plain
// (non-ErrSecretGone) error, simulating a transient failure (network/5xx/401). Refs in
// goneRefs error wrapping keyorix.ErrSecretGone, simulating a confirmed 404/403 from
// the upstream Keyorix server (#428).
type fakeFetcher struct {
	values   map[string][]byte
	failRefs map[string]bool
	goneRefs map[string]bool
}

func (f *fakeFetcher) FetchValue(_ context.Context, ref string) ([]byte, error) {
	if f.goneRefs[ref] {
		return nil, fmt.Errorf("ref %q gone: %w", ref, keyorix.ErrSecretGone)
	}
	if f.failRefs[ref] {
		return nil, errors.New("boom")
	}
	v, ok := f.values[ref]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, secretsv1alpha1.AddToScheme(s))
	return s
}

func newReconciler(t *testing.T, fetcher valueFetcher, objs ...client.Object) (*KeyorixSecretReconciler, client.Client) {
	t.Helper()
	s := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(objs...).
		Build()
	return &KeyorixSecretReconciler{
		Client: c,
		Scheme: s,
		// Trust the fixture's server so the (now fail-closed) allow-list passes; the
		// server-validation behavior itself is covered by TestValidateServer.
		AllowedServers: []string{"https://keyorix.internal"},
		newClient:      func(_, _ string) valueFetcher { return fetcher },
		hashKey:        []byte("test-fixture-hmac-key"),
	}, c
}

func ksFixture() *secretsv1alpha1.KeyorixSecret {
	return &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "app", Generation: 1},
		Spec: secretsv1alpha1.KeyorixSecretSpec{
			Server:         "https://keyorix.internal",
			TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: "token"},
			Target:         secretsv1alpha1.KeyorixSecretTarget{Name: "db-creds"},
			Data: []secretsv1alpha1.KeyorixSecretData{
				{SecretKey: "DB_PASSWORD", Ref: "app/production/db-password"},
				{SecretKey: "API_KEY", Ref: "app/production/api-key"},
			},
		},
	}
}

func tokenSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kx-token",
			Namespace: "app",
			Labels:    map[string]string{tokenSecretLabel: tokenSecretValue},
		},
		Data: map[string][]byte{"token": []byte("machine-tok")},
	}
}

func reconcile(t *testing.T, r *KeyorixSecretReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "db", Namespace: "app"},
	})
}

func TestReconcile_CreatesTargetSecretOwnedByCR(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())

	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.Positive(t, res.RequeueAfter, "reconcile requeues for the next refresh")

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("p4ss"), got.Data["DB_PASSWORD"])
	assert.Equal(t, []byte("k3y"), got.Data["API_KEY"])
	assert.Equal(t, corev1.SecretTypeOpaque, got.Type)

	// Owner reference makes the Secret garbage-collected when the CR is deleted.
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, "KeyorixSecret", got.OwnerReferences[0].Kind)
	assert.Equal(t, "db", got.OwnerReferences[0].Name)
	require.NotNil(t, got.OwnerReferences[0].Controller)
	assert.True(t, *got.OwnerReferences[0].Controller)

	// Status reflects success.
	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, "Ready", ks.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, ks.Status.Conditions[0].Status)
	assert.NotEmpty(t, ks.Status.SyncedHash)
	assert.NotNil(t, ks.Status.LastSyncTime)
	assert.Equal(t, int64(1), ks.Status.ObservedGeneration)
}

// TestReconcile_RefreshIntervalFloored pins #124: spec.refreshInterval had no
// minimum, so a CR author (or a compromised CR-writer) could set an absurdly
// small value (e.g. "1ms") and every successful reconcile would immediately
// requeue itself, driving a reconcile/API/etcd storm that starves the shared
// workqueue for every other KeyorixSecret in the cluster.
func TestReconcile_RefreshIntervalFloored(t *testing.T) {
	ks := ksFixture()
	ks.Spec.RefreshInterval = &metav1.Duration{Duration: time.Millisecond}
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, _ := newReconciler(t, fetcher, ks, tokenSecret())

	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, res.RequeueAfter, minRefreshInterval,
		"an absurdly small refreshInterval must be floored, not honored verbatim")
}

func TestReconcile_RefusesToOverwriteUnmanagedSecret(t *testing.T) {
	// A pre-existing Secret with the target name that the operator did NOT create.
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
		Data:       map[string][]byte{"OTHER": []byte("do-not-clobber")},
	}
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), foreign)

	_, err := reconcile(t, r)
	require.Error(t, err, "must refuse to adopt/overwrite an unmanaged Secret")

	// The foreign Secret's data is untouched — not clobbered with the synced keys.
	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("do-not-clobber"), got.Data["OTHER"])
	assert.NotContains(t, got.Data, "DB_PASSWORD")
}

func TestReconcile_DefaultsTargetNameToCR(t *testing.T) {
	ks := ksFixture()
	ks.Spec.Target.Name = "" // unset → defaults to the CR name "db"
	r, c := newReconciler(t, &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("x"), "app/production/api-key": []byte("y"),
	}}, ks, tokenSecret())

	_, err := reconcile(t, r)
	require.NoError(t, err)
	var got corev1.Secret
	assert.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &got))
}

func TestReconcile_FetchFailureFailsClosed(t *testing.T) {
	// One ref fails: the target Secret must NOT be written with a partial key set.
	fetcher := &fakeFetcher{
		values:   map[string][]byte{"app/production/db-password": []byte("p4ss")},
		failRefs: map[string]bool{"app/production/api-key": true},
	}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())

	_, err := reconcile(t, r)
	require.Error(t, err, "a fetch failure requeues with error for backoff")

	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	assert.Error(t, err, "no Secret is written when any value fails to fetch")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "SyncError", ks.Status.Conditions[0].Reason)
}

// TestReconcile_UpstreamGoneWipesTargetSecret pins #428: a fetch failure that
// AFFIRMATIVELY indicates the upstream secret is gone (404/403, wrapped as
// keyorix.ErrSecretGone) must actively delete the previously synced target Secret —
// otherwise every workload mounting it goes on reading a revoked/deleted value
// indefinitely, with the CR's Ready condition the only (easy-to-miss) hint anything is
// wrong.
func TestReconcile_UpstreamGoneWipesTargetSecret(t *testing.T) {
	// First reconcile succeeds and creates the target Secret normally.
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"precondition: the target Secret exists after a successful sync")

	// The upstream secret is now confirmed gone (404/403) on the next reconcile.
	fetcher.goneRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err, "a confirmed-gone upstream ref still requeues with error for backoff")
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	assert.Error(t, err, "the target Secret must be wiped once the upstream secret is confirmed gone")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "UpstreamSecretGone", ks.Status.Conditions[0].Reason,
		"the status reason must distinguish a confirmed wipe from an ordinary SyncError")
}

// TestReconcile_TransientFetchFailureLeavesTargetSecretUntouched pins #428's other
// half: a transient failure (network error, timeout, 5xx, or an ambiguous 401) must
// NOT touch a previously synced target Secret. Wiping it on every hiccup would cause
// unnecessary outages for every workload depending on it.
func TestReconcile_TransientFetchFailureLeavesTargetSecretUntouched(t *testing.T) {
	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"),
		"app/production/api-key":     []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	var before corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &before))

	// A transient failure on the next reconcile — NOT wrapping ErrSecretGone.
	fetcher.failRefs = map[string]bool{"app/production/db-password": true}

	_, err = reconcile(t, r)
	require.Error(t, err)
	assert.False(t, errors.Is(err, keyorix.ErrSecretGone), "a transient failure must not be classified as gone")

	var after corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &after),
		"the target Secret must still exist after a transient fetch failure")
	assert.Equal(t, before.Data, after.Data, "a transient failure must not alter the previously synced values")

	var ks secretsv1alpha1.KeyorixSecret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, &ks))
	require.Len(t, ks.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, ks.Status.Conditions[0].Status)
	assert.Equal(t, "SyncError", ks.Status.Conditions[0].Reason, "a transient failure keeps the generic SyncError reason")
}

// A target Secret this operator does NOT manage (no ManagedByLabel — applySecret
// already refuses to adopt it) must never be deleted, even when the upstream secret is
// confirmed gone: it isn't ours to touch, and it may belong to an unrelated workload
// that merely collides on name.
func TestReconcile_UpstreamGoneDoesNotDeleteUnmanagedSecret(t *testing.T) {
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "app"},
		Data:       map[string][]byte{"OTHER": []byte("do-not-touch")},
	}
	fetcher := &fakeFetcher{goneRefs: map[string]bool{"app/production/db-password": true}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), foreign)

	_, err := reconcile(t, r)
	require.Error(t, err)
	assert.True(t, errors.Is(err, keyorix.ErrSecretGone))

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got),
		"an unmanaged Secret sharing the target name must not be deleted")
	assert.Equal(t, []byte("do-not-touch"), got.Data["OTHER"])
}

// TestReconcile_TokenSecretReadUsesAPIReader pins #124: the token Secret lookup
// must go through the uncached APIReader (when set), not the shared/cached
// Client — the shared cache is scoped to only Secrets this operator manages, so
// an arbitrary token Secret would never appear there in production. Prove the
// reconciler actually reads via APIReader by giving it a SEPARATE fake client
// that holds the token Secret while the main Client does not.
func TestReconcile_TokenSecretReadUsesAPIReader(t *testing.T) {
	s := testScheme(t)
	mainClient := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
		WithObjects(ksFixture()). // no token Secret here
		Build()
	apiReader := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(tokenSecret()). // the token Secret lives only in the "uncached" reader
		Build()

	r := &KeyorixSecretReconciler{
		Client:         mainClient,
		Scheme:         s,
		APIReader:      apiReader,
		AllowedServers: []string{"https://keyorix.internal"},
		newClient: func(_, _ string) valueFetcher {
			return &fakeFetcher{values: map[string][]byte{
				"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
			}}
		},
		hashKey: []byte("test-fixture-hmac-key"),
	}

	_, err := reconcile(t, r)
	require.NoError(t, err, "the token Secret must be found via APIReader even though it is absent from Client")
}

func TestReconcile_MissingTokenSecretFails(t *testing.T) {
	// No token Secret present.
	r, _ := newReconciler(t, &fakeFetcher{}, ksFixture())
	_, err := reconcile(t, r)
	require.Error(t, err)
}

func TestReconcile_DeletedCRIsNoOp(t *testing.T) {
	// No KeyorixSecret object at all → reconcile returns cleanly (owned Secret is GC'd).
	r, _ := newReconciler(t, &fakeFetcher{})
	res, err := reconcile(t, r)
	require.NoError(t, err)
	assert.Zero(t, res.RequeueAfter)
}

func TestReconcile_RemovedKeyIsPruned(t *testing.T) {
	// First sync writes two keys; dropping one from spec prunes it on the next sync,
	// because the operator owns the whole data set.
	ks := ksFixture()
	r, c := newReconciler(t, &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.NoError(t, err)

	// Drop API_KEY from the spec and reconcile again.
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db", Namespace: "app"}, ks))
	ks.Spec.Data = ks.Spec.Data[:1]
	require.NoError(t, c.Update(context.Background(), ks))
	_, err = reconcile(t, r)
	require.NoError(t, err)

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Contains(t, got.Data, "DB_PASSWORD")
	assert.NotContains(t, got.Data, "API_KEY", "a dropped mapping is pruned from the Secret")
}

func TestHashData_StableAndSensitive(t *testing.T) {
	key := []byte("test-hmac-key")
	a := map[string][]byte{"x": []byte("1"), "y": []byte("2")}
	b := map[string][]byte{"y": []byte("2"), "x": []byte("1")}
	assert.Equal(t, hashData(key, a), hashData(key, b), "hash is independent of map iteration order")
	assert.NotEqual(t, hashData(key, a), hashData(key, map[string][]byte{"x": []byte("1"), "y": []byte("3")}))
}

// TestHashData_KeyedAgainstBruteForce pins #124: status.syncedHash is a CR
// subresource commonly readable without any RBAC on the underlying Secret. A
// plain, unkeyed sha256 there would let a CR-getter brute-force a low-entropy
// value offline with zero Secret-read access. Keying the hash means an
// observer who only ever sees the hash (never the key, which lives in the
// operator process's memory) cannot precompute/verify guesses against it.
func TestHashData_KeyedAgainstBruteForce(t *testing.T) {
	data := map[string][]byte{"password": []byte("hunter2")}
	h1 := hashData([]byte("key-one"), data)
	h2 := hashData([]byte("key-two"), data)
	assert.NotEqual(t, h1, h2, "the same data must hash differently under a different key")

	// An attacker who only knows a candidate value and the algorithm (sha256,
	// no key) cannot reproduce a keyed hash — confirms this isn't just a plain
	// sha256 in disguise.
	plainSHA := sha256.Sum256([]byte("password\x00hunter2\x00"))
	assert.NotEqual(t, hex.EncodeToString(plainSHA[:]), h1)
}

// validateServer is the confused-deputy guard: the operator must only ever send a token
// to an https destination it was explicitly configured to trust, so a tenant who can
// create a CR cannot redirect a (possibly arbitrary) namespace Secret's value to an
// attacker server.
func TestValidateServer(t *testing.T) {
	allow := &KeyorixSecretReconciler{AllowedServers: []string{"https://keyorix.internal", "https://kx.example.com/"}}
	cases := []struct {
		name    string
		r       *KeyorixSecretReconciler
		server  string
		wantErr bool
	}{
		{"allowed host", allow, "https://keyorix.internal", false},
		{"allowed host trailing-slash config", allow, "https://kx.example.com", false},
		{"http rejected", allow, "http://keyorix.internal", true},
		{"not in allow-list rejected", allow, "https://attacker.example", true},
		{"empty allow-list rejects everything (fail closed)", &KeyorixSecretReconciler{}, "https://keyorix.internal", true},
		{"garbage rejected", allow, "::nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.validateServer(tc.server)
			if tc.wantErr && err == nil {
				t.Errorf("validateServer(%q) = nil; want error", tc.server)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateServer(%q) = %v; want nil", tc.server, err)
			}
		})
	}
}

// A CR pointing at an untrusted server is rejected BEFORE the operator reads the token
// Secret — so it cannot be used to exfiltrate a namespace Secret to an attacker.
func TestReconcile_RejectsUntrustedServer(t *testing.T) {
	ks := ksFixture()
	ks.Spec.Server = "https://attacker.example"
	r, c := newReconciler(t, &fakeFetcher{}, ks, tokenSecret())
	_, err := reconcile(t, r)
	require.Error(t, err, "a CR with a non-allowlisted server must fail the reconcile")

	// No target Secret was written.
	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	require.Error(t, err, "no Secret is created for a rejected server")
}

// #184 (confused deputy, second half): even with validateServer pinning the
// destination, a CRD-write-only principal (no core-Secret RBAC of their own) must not
// be able to point tokenSecretRef at an arbitrary pre-existing Secret and have the
// operator's cluster-wide Secret-read RBAC ship its bytes to the (trusted) Keyorix
// server. Only a Secret explicitly labeled as a token source may be resolved.
func TestReconcile_RejectsUnlabeledTokenSecret(t *testing.T) {
	unlabeled := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kx-token", Namespace: "app"}, // no label
		Data:       map[string][]byte{"token": []byte("some-secret-value")},
	}
	r, c := newReconciler(t, &fakeFetcher{}, ksFixture(), unlabeled)

	_, err := reconcile(t, r)
	require.Error(t, err, "an unlabeled Secret must not be usable as tokenSecretRef")
	assert.Contains(t, err.Error(), tokenSecretLabel)

	var got corev1.Secret
	err = c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got)
	require.Error(t, err, "no Secret is created when the token source is unlabeled")
}

// A Secret carrying an unrelated/incorrect label value (not exactly the required
// marker) is treated the same as unlabeled — no partial-match bypass.
func TestReconcile_RejectsTokenSecretWithWrongLabelValue(t *testing.T) {
	wrongLabel := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kx-token",
			Namespace: "app",
			Labels:    map[string]string{tokenSecretLabel: "false"},
		},
		Data: map[string][]byte{"token": []byte("some-secret-value")},
	}
	r, _ := newReconciler(t, &fakeFetcher{}, ksFixture(), wrongLabel)
	_, err := reconcile(t, r)
	require.Error(t, err)
}

// #185: a same-named Secret already owned (controller ref) by a DIFFERENT KeyorixSecret
// CR must never be silently re-adopted by this CR, even though it already carries the
// operator's managed-by label (set by the other CR's earlier reconcile). This is the
// second line of defense beyond the managed-by label check: SetControllerReference
// itself refuses to move a controller ref from one owner to another.
func TestReconcile_RefusesToAdoptSecretOwnedByAnotherCR(t *testing.T) {
	other := &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "other-cr", Namespace: "app", UID: "other-uid"},
	}
	owned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-creds",
			Namespace: "app",
			Labels:    map[string]string{ManagedByLabel: ManagedByValue},
		},
		Data: map[string][]byte{"OTHER": []byte("owned-by-other-cr")},
	}
	// Give `owned` a real controller owner reference to `other`, mirroring what a prior
	// reconcile of the other CR would have set.
	s := testScheme(t)
	require.NoError(t, controllerutil.SetControllerReference(other, owned, s))

	fetcher := &fakeFetcher{values: map[string][]byte{
		"app/production/db-password": []byte("p4ss"), "app/production/api-key": []byte("k3y"),
	}}
	r, c := newReconciler(t, fetcher, ksFixture(), tokenSecret(), owned)

	_, err := reconcile(t, r)
	require.Error(t, err, "must refuse to steal ownership of a Secret controlled by a different CR")

	var got corev1.Secret
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "db-creds", Namespace: "app"}, &got))
	assert.Equal(t, []byte("owned-by-other-cr"), got.Data["OTHER"], "the other CR's Secret data must be untouched")
	assert.NotContains(t, got.Data, "DB_PASSWORD")
	require.Len(t, got.OwnerReferences, 1)
	assert.Equal(t, "other-cr", got.OwnerReferences[0].Name, "ownership must not have moved to the new CR")
}
