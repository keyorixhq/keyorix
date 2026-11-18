package controller

// reconcile_idempotent_scope_redgreen_test.go is the red/green proof for the two NEW
// oracles in FuzzReconcileIdempotentScopeConfined: convergence/idempotence and scope.
// "A guard nobody has watched fail is not a guard" (CLAUDE.md) — each oracle is shown
// GREEN on a known-good case and RED on a known-bad one.

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
)

// flakyValueFetcher returns a DIFFERENT value on every call — the adversarial "upstream
// is not stable between reconciles" shape. A correct reconciler is idempotent only when
// the upstream is stable; this models the negative so the idempotence oracle can be shown
// to fire. (It is a legitimate hostile input shape, not a production-code plant.)
type flakyValueFetcher struct{ n atomic.Int64 }

func (f *flakyValueFetcher) FetchValue(_ context.Context, _ string) ([]byte, error) {
	return []byte("value-" + strconv.FormatInt(f.n.Add(1), 10)), nil
}

// reconcileTwiceRV builds a healthy single-entry CR in tenant-a, reconciles it twice with
// the given fetcher, and returns the target Secret's ResourceVersion after each pass.
func reconcileTwiceRV(t *testing.T, fetch valueFetcher) (rv1, rv2 string) {
	t.Helper()
	ks := &secretsv1alpha1.KeyorixSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "attacker", Namespace: attackerNS, UID: attackerUID, Generation: 1},
		Spec: secretsv1alpha1.KeyorixSecretSpec{
			Server:         "https://keyorix.internal",
			TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: "token"},
			Target:         secretsv1alpha1.KeyorixSecretTarget{Name: "t"},
			Data:           []secretsv1alpha1.KeyorixSecretData{{SecretKey: "k", Ref: "okref"}},
			PrunePolicy:    secretsv1alpha1.PrunePolicyDelete,
		},
	}
	tok := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kx-token", Namespace: attackerNS, Labels: map[string]string{tokenSecretLabel: tokenSecretValue}},
		Data:       map[string][]byte{"token": []byte("machine-tok")},
	}
	s := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).WithObjects(ks, tok).Build()
	rr := &KeyorixSecretReconciler{
		Client: c, Scheme: s, AllowedServers: []string{"https://keyorix.internal"},
		newClient: func(_, _ string) valueFetcher { return fetch }, hashKey: []byte("fuzz-fixture-hmac-key"),
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "attacker", Namespace: attackerNS}}
	if _, err := rr.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("pass1 reconcile: %v", err)
	}
	rv1, _ = targetSecretRV(t, c, "t")
	if _, err := rr.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("pass2 reconcile: %v", err)
	}
	rv2, _ = targetSecretRV(t, c, "t")
	return rv1, rv2
}

// TestIdempotenceOracleRedGreen: GREEN with a stable upstream (RV unchanged on pass 2),
// RED with a flaky upstream (RV changes — the oracle's trip condition holds).
func TestIdempotenceOracleRedGreen(t *testing.T) {
	t.Run("green_stable_upstream_converges", func(t *testing.T) {
		rv1, rv2 := reconcileTwiceRV(t, &canaryFuzzFetcher{})
		if rv1 == "" {
			t.Fatal("target Secret was not created on pass 1")
		}
		if rv1 != rv2 {
			t.Fatalf("GREEN FAILED: stable upstream still rewrote the Secret (rv %q -> %q) — reconcile is not idempotent", rv1, rv2)
		}
	})
	t.Run("red_flaky_upstream_oracle_fires", func(t *testing.T) {
		rv1, rv2 := reconcileTwiceRV(t, &flakyValueFetcher{})
		if rv1 == rv2 {
			t.Fatalf("RED FAILED: a non-deterministic upstream did NOT change the Secret RV (%q) — the idempotence oracle would not have fired, so it proves nothing", rv1)
		}
		// rv1 != rv2 here is exactly the condition FuzzReconcileIdempotentScopeConfined
		// fails on; the oracle catches a non-convergent reconcile.
	})
}

// TestScopeOracleRedGreen: GREEN when every recorded op is in-namespace, RED when any op
// names another namespace or an unscoped (cluster-wide) List appears.
func TestScopeOracleRedGreen(t *testing.T) {
	green := []apiOp{
		{"Get", attackerNS, "attacker"},
		{"Get", attackerNS, "kx-token"},
		{"List", attackerNS, ""},
		{"Create", attackerNS, "t"},
	}
	if op, bad := scopeViolation(green, attackerNS); bad {
		t.Fatalf("GREEN FAILED: in-namespace ops flagged as a scope violation: %+v", op)
	}
	reds := map[string][]apiOp{
		"cross_namespace_get":    append(append([]apiOp{}, green...), apiOp{"Get", tenantB, "kx-token"}),
		"cross_namespace_delete": append(append([]apiOp{}, green...), apiOp{"Delete", tenantB, "victim-b-secret"}),
		"cluster_wide_list":      append(append([]apiOp{}, green...), apiOp{"List", "", ""}),
	}
	for name, ops := range reds {
		t.Run(name, func(t *testing.T) {
			if _, bad := scopeViolation(ops, attackerNS); !bad {
				t.Fatalf("RED FAILED: a cross-tenant op was NOT flagged — the scope oracle is vacuous")
			}
		})
	}
}
