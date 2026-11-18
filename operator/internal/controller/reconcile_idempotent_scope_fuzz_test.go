package controller

// reconcile_idempotent_scope_fuzz_test.go closes the two oracle gaps the existing
// operator fuzz targets (FuzzReconcileAuthzBoundary, FuzzReconcileHostileK8sAPI)
// leave open, verified against those files before this was written:
//
//   - IDEMPOTENCE / CONVERGENCE (task oracle #5): neither existing target ever runs
//     Reconcile more than once, so nothing proves a second reconcile over an
//     already-synced world is a no-op. A reconciler that rewrote the target Secret
//     (or oscillated its .status terminal state) on every pass would churn etcd and
//     the single shared workqueue for every tenant cluster-wide — the exact DoS the
//     minRefreshInterval floor and maxConcurrentReconciles cap exist to bound — yet
//     pass unseen. Here the SAME input is reconciled twice against a STABLE upstream
//     and the target Secret's ResourceVersion and the Ready terminal reason must not
//     move on the second pass.
//
//   - STRONG SCOPE CONFINEMENT (task oracles #1 + #2): FuzzReconcileAuthzBoundary's
//     "no Secret outside tenant-a" check is vacuous — its fake cluster holds NO object
//     outside tenant-a, so a cross-namespace READ is invisible and a cross-namespace
//     WRITE has nothing to collide with. Here a fully-populated SECOND tenant namespace
//     (tenant-b: a victim Secret named identically to the attacker's target, a token
//     Secret named identically to the attacker's token, and a peer CR sharing the
//     token ref) baits every cross-tenant primitive, and an interceptor RECORDS the
//     namespace of every single Kubernetes API object operation the reconcile issues.
//     The oracle: every Get/Update/Create/Delete names tenant-a, and every List is
//     scoped InNamespace(tenant-a) — the reconciler only ever derives a NamespacedName
//     or a list scope from ks.Namespace, so a namespaced-only actor can never make it
//     reach tenant-b.
//
// Resguard note (stated in the OP1 report too): operator/ is a SEPARATE Go module with
// no dependency on the main module, so internal/fuzzutil/resguard cannot be imported
// here without a production go.mod change. The bounded-work / no-goroutine-leak oracle
// (#6) therefore uses local in-process meters (a FetchValue counter and a
// runtime.NumGoroutine delta); the resguard-wired resource pilot lives in
// internal/k8ssync, which is module-clean.

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
)

// tenantB is the second tenant whose objects the reconcile must NEVER read or write.
const (
	tenantB      = "tenant-b"
	victimBUID   = "victim-b-uid-0003"
	victimBDataK = "keepB"
	victimBDataV = "TENANT-B-DO-NOT-TOUCH"
)

// apiOp is one recorded Kubernetes API object operation and the namespace it named.
type apiOp struct {
	verb string
	ns   string
	name string
}

// opRecorder records the namespace of every object operation the reconcile issues, so
// the scope oracle can assert none of them ever reached tenant-b. Guarded for the single
// reconcile goroutine; the fake client is otherwise synchronous.
type opRecorder struct {
	ops []apiOp
}

func (rec *opRecorder) add(verb, ns, name string) { rec.ops = append(rec.ops, apiOp{verb, ns, name}) }

// FuzzReconcileIdempotentScopeConfined drives a full reconcile twice over a fake cluster
// that ALSO holds a populated tenant-b, with the attacker-controlled CR fields and the
// per-ref upstream outcome derived from the fuzz input. Oracles:
//
//  1. SCOPE — every object Get/Update/Create/Delete names tenant-a; every List is scoped
//     to tenant-a. No tenant-b object is ever named or listed.
//  2. CROSS-TENANT INTEGRITY — tenant-b's victim Secret and token Secret are byte-for-byte
//     unchanged after both passes.
//  3. IDEMPOTENCE / CONVERGENCE — with a stable upstream, the target Secret's
//     ResourceVersion does not change on the second pass, and the Ready reason is
//     identical across the two passes (converged terminal state, no rewrite, no flap).
//  4. CANARY — the fetched value never appears in .status, an Event, or the error, on
//     either pass.
//  5. BOUNDED WORK / NO LEAK — upstream fetches stay bounded and no goroutine is leaked
//     across the two reconciles.
//  6. No panic.
//
// What it does NOT verify: real apiserver scoping/RBAC (the fake client enforces none —
// the oracle proves the reconciler's OWN code never NAMES another namespace, which is the
// property that would survive on a real cluster where RBAC is cluster-wide by design);
// CRD admission (drives below it); cross-PROCESS concurrency (one synchronous reconcile);
// and operator stdout logs (value-free by static construction, not re-scanned here).
func FuzzReconcileIdempotentScopeConfined(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{9, 'm', 'y', '-', 't', 'a', 'r', 'g', 'e', 't', 0, 1, 'k', 5, 'o', 'k', 'r', 'e', 'f', 0, 0, 0, 1, 1})
	// target.name collides with the tenant-b victim Secret name "victim-b-secret":
	f.Add([]byte{14, 'v', 'i', 'c', 't', 'i', 'm', '-', 'b', '-', 's', 'e', 'c', 'r', 'e', 't', 0, 1, 'k', 5, 'g', 'o', 'n', 'e', 'x', 1, 0, 0, 1, 1})
	f.Add(bytes32(0x5A))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := &byteReader{b: data}

		targetName := r.str(64)
		nEntries := int(r.u8()%4) + 1
		var entries []secretsv1alpha1.KeyorixSecretData
		gone := map[string]bool{}
		unauth := map[string]bool{}
		fail := map[string]bool{}
		for k := range nEntries {
			sk := r.str(16)
			if sk == "" {
				sk = "k" + string(rune('A'+k))
			}
			ref := r.str(48)
			entries = append(entries, secretsv1alpha1.KeyorixSecretData{SecretKey: sk, Ref: ref})
			switch r.u8() % 5 {
			case 1:
				gone[ref] = true
			case 2:
				unauth[ref] = true
			case 3:
				fail[ref] = true
			}
		}
		var prune secretsv1alpha1.PrunePolicy
		switch r.u8() % 3 {
		case 0:
			prune = secretsv1alpha1.PrunePolicyDelete
		case 1:
			prune = secretsv1alpha1.PrunePolicyKeep
		}
		onSuspend := secretsv1alpha1.OnSuspendRetain
		if r.u8()%2 == 0 {
			onSuspend = secretsv1alpha1.OnSuspendClear
		}
		tokenKey := "token"
		if r.u8()%4 == 0 {
			tokenKey = r.str(16)
		}
		annos := map[string]string{}
		if r.u8()%3 == 0 {
			annos[confirmPruneAnnotation] = r.str(40)
		}

		attacker := &secretsv1alpha1.KeyorixSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "attacker", Namespace: attackerNS, UID: attackerUID,
				Generation: 1, Annotations: annos,
			},
			Spec: secretsv1alpha1.KeyorixSecretSpec{
				Server:         "https://keyorix.internal",
				TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: tokenKey},
				Target:         secretsv1alpha1.KeyorixSecretTarget{Name: targetName},
				Data:           entries,
				PrunePolicy:    prune,
				OnSuspend:      onSuspend,
			},
		}
		tokA := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kx-token", Namespace: attackerNS,
				Labels: map[string]string{tokenSecretLabel: tokenSecretValue},
			},
			Data: map[string][]byte{"token": []byte("machine-tok-A"), tokenKey: []byte("machine-tok-A")},
		}

		// tenant-b bait: a victim Secret named identically to the attacker's target, a
		// token Secret named identically to the attacker's token (so a cross-namespace
		// token read would resolve), and a peer CR sharing the token ref (so an unscoped
		// mass-revocation List would pull it in). None may ever be named by the reconcile.
		victimBName := "victim-b-secret"
		victimB := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: victimBName, Namespace: tenantB,
				Labels: map[string]string{ManagedByLabel: ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: secretsv1alpha1.GroupVersion.String(), Kind: "KeyorixSecret",
					Name: "victim-b-cr", UID: victimBUID, Controller: boolptr(true),
				}},
			},
			Data: map[string][]byte{victimBDataK: []byte(victimBDataV)},
		}
		// Also place a tenant-b Secret that collides with the attacker's CHOSEN target
		// name, when that name differs from the fixed victim name, so a cross-namespace
		// write under the attacker's own target name has something to clobber.
		var victimBCollide *corev1.Secret
		if targetName != "" && targetName != victimBName {
			victimBCollide = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: targetName, Namespace: tenantB,
					Labels: map[string]string{ManagedByLabel: ManagedByValue},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: secretsv1alpha1.GroupVersion.String(), Kind: "KeyorixSecret",
						Name: "victim-b-cr", UID: victimBUID, Controller: boolptr(true),
					}},
				},
				Data: map[string][]byte{victimBDataK: []byte(victimBDataV)},
			}
		}
		tokB := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kx-token", Namespace: tenantB,
				Labels: map[string]string{tokenSecretLabel: tokenSecretValue},
			},
			Data: map[string][]byte{"token": []byte("TENANT-B-TOKEN"), tokenKey: []byte("TENANT-B-TOKEN")},
		}
		peerB := &secretsv1alpha1.KeyorixSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "peer-b", Namespace: tenantB, UID: "peer-b-uid"},
			Spec: secretsv1alpha1.KeyorixSecretSpec{
				Server:         "https://keyorix.internal",
				TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: tokenKey},
				Data:           []secretsv1alpha1.KeyorixSecretData{{SecretKey: "k", Ref: "peerb-ref"}},
				PrunePolicy:    secretsv1alpha1.PrunePolicyDelete,
			},
		}

		objs := []client.Object{attacker, tokA, victimB, tokB, peerB}
		if victimBCollide != nil {
			objs = append(objs, victimBCollide)
		}

		s := testScheme(t)
		inner := fake.NewClientBuilder().
			WithScheme(s).
			WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
			WithObjects(objs...).
			Build()

		rec := &opRecorder{}
		c := interceptor.NewClient(inner, interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				rec.add("Get", key.Namespace, key.Name)
				return cl.Get(ctx, key, obj, opts...)
			},
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				lo := &client.ListOptions{}
				lo.ApplyOptions(opts)
				rec.add("List", lo.Namespace, "")
				return cl.List(ctx, list, opts...)
			},
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				rec.add("Create", obj.GetNamespace(), obj.GetName())
				return cl.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				rec.add("Update", obj.GetNamespace(), obj.GetName())
				return cl.Update(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				rec.add("Delete", obj.GetNamespace(), obj.GetName())
				return cl.Delete(ctx, obj, opts...)
			},
		})

		fetcher := &countingFetcher{inner: &canaryFuzzFetcher{gone: gone, unauth: unauth, fail: fail}}
		evRec := events.NewFakeRecorder(512)
		rr := &KeyorixSecretReconciler{
			Client:         c,
			Scheme:         s,
			AllowedServers: []string{"https://keyorix.internal"},
			newClient:      func(_, _ string) valueFetcher { return fetcher },
			hashKey:        []byte("fuzz-fixture-hmac-key"),
			Recorder:       evRec,
		}

		g0 := runtime.NumGoroutine()
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "attacker", Namespace: attackerNS}}

		// Pass 1.
		_, rerr1 := rr.Reconcile(context.Background(), req)
		rv1, exists1 := targetSecretRV(t, inner, targetName)
		reason1 := currentReadyReason(t, inner)

		// Pass 2 over the now-already-synced world.
		_, rerr2 := rr.Reconcile(context.Background(), req)
		rv2, exists2 := targetSecretRV(t, inner, targetName)
		reason2 := currentReadyReason(t, inner)

		g1 := runtime.NumGoroutine()

		// (1) SCOPE: no operation ever named or listed another namespace.
		if op, bad := scopeViolation(rec.ops, attackerNS); bad {
			t.Fatalf("SCOPE: reconcile issued a %s on namespace %q name %q — it must only ever touch its own namespace %q (a namespaced actor could reach another tenant)", op.verb, op.ns, op.name, attackerNS)
		}

		// (2) CROSS-TENANT INTEGRITY: tenant-b objects byte-identical.
		assertTenantBUntouched(t, inner, victimBName, targetName)

		// (3) IDEMPOTENCE / CONVERGENCE.
		if exists1 != exists2 {
			t.Fatalf("CONVERGENCE: target Secret existence flipped between passes (pass1 exists=%v, pass2 exists=%v) — reconcile oscillates", exists1, exists2)
		}
		if exists1 && exists2 && rv1 != rv2 {
			t.Fatalf("IDEMPOTENCE: target Secret %q ResourceVersion changed on the second reconcile (%q -> %q) over a STABLE upstream — a non-idempotent rewrite that churns etcd/the workqueue every pass", targetName, rv1, rv2)
		}
		if reason1 != reason2 {
			t.Fatalf("CONVERGENCE: Ready reason changed between identical passes (%q -> %q) — the terminal state does not converge", reason1, reason2)
		}

		// (4) CANARY on both passes.
		assertNoCanaryLeak(t, inner, evRec, rerr1)
		assertNoCanaryLeak(t, inner, evRec, rerr2)

		// (5) BOUNDED WORK / NO LEAK.
		if n := fetcher.calls.Load(); n > int64(massPruneProbeCap)+16 {
			t.Fatalf("BOUNDED WORK: %d upstream fetches across two reconciles exceeds the cap (massPruneProbeCap=%d + own data) — unbounded fan-out", n, massPruneProbeCap)
		}
		if g1 > g0+8 {
			t.Fatalf("GOROUTINE LEAK: %d goroutines before, %d after two reconciles — the reconcile leaked goroutines", g0, g1)
		}
	})
}

// scopeViolation returns the first recorded operation that reaches outside ownNS: any
// Get/Update/Create/Delete naming another namespace, or any List not scoped to ownNS.
// A cluster-scoped List (empty namespace) is a violation because it would return every
// tenant's objects. This is the exact oracle the fuzz target enforces; the red/green
// test exercises it directly so the guard is not vacuous.
func scopeViolation(ops []apiOp, ownNS string) (apiOp, bool) {
	for _, op := range ops {
		if op.ns != ownNS {
			return op, true
		}
	}
	return apiOp{}, false
}

// targetSecretRV returns the target Secret's ResourceVersion and whether it exists. An
// empty target name means the CR's Name is the target name (Reconcile's own default).
func targetSecretRV(t *testing.T, c client.Client, targetName string) (string, bool) {
	t.Helper()
	name := targetName
	if name == "" {
		name = "attacker"
	}
	var sec corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Namespace: attackerNS, Name: name}, &sec)
	if err != nil {
		return "", false
	}
	return sec.ResourceVersion, true
}

// currentReadyReason reads the attacker CR's Ready condition reason after a reconcile.
func currentReadyReason(t *testing.T, c client.Client) string {
	t.Helper()
	var got secretsv1alpha1.KeyorixSecret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: attackerNS, Name: "attacker"}, &got); err != nil {
		return ""
	}
	return readyReason(&got)
}

// assertTenantBUntouched fails if any tenant-b Secret changed. victimBName is the fixed
// victim; targetName (when it differs) is the collision bait placed in tenant-b too.
func assertTenantBUntouched(t *testing.T, c client.Client, victimBName, targetName string) {
	t.Helper()
	check := func(name string) {
		var sec corev1.Secret
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: tenantB, Name: name}, &sec); err != nil {
			t.Fatalf("CROSS-TENANT: tenant-b Secret %q was DELETED by the reconcile: %v", name, err)
		}
		if string(sec.Data[victimBDataK]) != victimBDataV || len(sec.Data) != 1 {
			t.Fatalf("CROSS-TENANT: tenant-b Secret %q data was MODIFIED by the reconcile: %v", name, sec.Data)
		}
	}
	check(victimBName)
	if targetName != "" && targetName != victimBName {
		check(targetName)
	}
}

// assertNoCanaryLeak scans .status, Events and the reconcile error for the canary value.
func assertNoCanaryLeak(t *testing.T, c client.Client, evRec *events.FakeRecorder, rerr error) {
	t.Helper()
	var got secretsv1alpha1.KeyorixSecret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: attackerNS, Name: "attacker"}, &got); err == nil {
		if blob, _ := json.Marshal(got.Status); strings.Contains(string(blob), canaryValue) {
			t.Fatalf("CANARY LEAK in .status: %s", blob)
		}
	}
	if rerr != nil && strings.Contains(rerr.Error(), canaryValue) {
		t.Fatalf("CANARY LEAK in reconcile error: %v", rerr)
	}
	for {
		select {
		case ev := <-evRec.Events:
			if strings.Contains(ev, canaryValue) {
				t.Fatalf("CANARY LEAK in Event: %s", ev)
			}
		default:
			return
		}
	}
}
