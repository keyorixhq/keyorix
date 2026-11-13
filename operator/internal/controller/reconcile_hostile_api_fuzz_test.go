package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
)

// countingFetcher wraps canaryFuzzFetcher and counts FetchValue calls so the harness can
// assert the reconcile's outbound work stays bounded under a hostile/oversized cluster
// (massRevocationSuspected probes every token-sharing peer, capped at massPruneProbeCap).
type countingFetcher struct {
	inner *canaryFuzzFetcher
	calls atomic.Int64
}

func (f *countingFetcher) FetchValue(ctx context.Context, ref string) ([]byte, error) {
	f.calls.Add(1)
	return f.inner.FetchValue(ctx, ref)
}

// hostileErr maps a fuzz byte to an injected Kubernetes API error (or nil = pass through).
// These are the adversarial response shapes a compromised/racing apiserver or a
// delete-blocking webhook can produce: a Conflict (optimistic-concurrency loss), a
// NotFound (object deleted while reconciling), a ServerTimeout, or an opaque error.
func hostileErr(b byte) error {
	gr := schema.GroupResource{Resource: "secrets"}
	switch b % 6 {
	case 1:
		return apierrors.NewConflict(gr, "x", errors.New("the object has been modified"))
	case 2:
		return apierrors.NewNotFound(gr, "x")
	case 3:
		return apierrors.NewServerTimeout(gr, "get", 1)
	case 4:
		return errors.New("hostile synthetic apiserver error")
	}
	return nil
}

// decider hands out the next fuzz byte, cycling, so each intercepted API call gets a
// deterministic (replayable) hostile-or-passthrough decision from the fuzz input.
type decider struct {
	b []byte
	i int
}

func (d *decider) next() byte {
	if len(d.b) == 0 {
		return 0
	}
	v := d.b[d.i%len(d.b)]
	d.i++
	return v
}

// FuzzReconcileHostileK8sAPI drives the reconcile against a fake Kubernetes API whose
// Get/List/Update/Delete/Create responses are adversarially perturbed by the fuzz input
// (injected Conflict / NotFound / ServerTimeout / opaque errors), in a cluster that also
// holds an OVERSIZED set of token-sharing peer KeyorixSecrets (to exercise the
// mass-revocation breaker's List + per-peer probe fan-out). Oracles:
//
//  1. No panic under any interleaving of injected failures.
//  2. BOUNDED WORK — the number of upstream value fetches never exceeds
//     massPruneProbeCap + the CR's own data entries + a small slack, no matter how many
//     peers share the token. An unbounded fan-out would be a DoS amplifier.
//  3. CROSS-TENANT INTEGRITY — the victim Secret (owned by a different CR) is never left
//     mutated. A hostile apiserver response must not trick the reconciler into writing or
//     clearing a Secret it does not control. (It may be deleted only if the injected
//     interceptor itself returned success for a Delete the reconciler would NOT have
//     issued — which it cannot, since the reconciler only Deletes a Secret it controls;
//     so the victim's data, if present, must be unchanged.)
//  4. CANARY — no fetched value reaches .status / Events / the returned error.
//
// What this does NOT verify: real apiserver semantics (watch cache staleness, admission
// webhooks, true optimistic concurrency) — only that the reconciler tolerates these
// response shapes without panicking, unbounded fan-out, cross-tenant writes, or leaks.
func FuzzReconcileHostileK8sAPI(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4, 0, 5})
	f.Add([]byte{2, 2, 2, 2, 2, 2})
	f.Add(bytes32(0x07))

	f.Fuzz(func(t *testing.T, data []byte) {
		d := &decider{b: data}

		attacker := &secretsv1alpha1.KeyorixSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "attacker", Namespace: attackerNS, UID: attackerUID, Generation: 1},
			Spec: secretsv1alpha1.KeyorixSecretSpec{
				Server:         "https://keyorix.internal",
				TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: "token"},
				Target:         secretsv1alpha1.KeyorixSecretTarget{Name: "attacker-target"},
				Data:           []secretsv1alpha1.KeyorixSecretData{{SecretKey: "k", Ref: "gonex"}},
				PrunePolicy:    secretsv1alpha1.PrunePolicyDelete,
			},
		}
		victim := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: victimSecret, Namespace: attackerNS,
				Labels: map[string]string{ManagedByLabel: ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: secretsv1alpha1.GroupVersion.String(), Kind: "KeyorixSecret",
					Name: "victim-cr", UID: victimUID, Controller: boolptr(true),
				}},
			},
			Data: map[string][]byte{victimDataK: []byte(victimDataV)},
		}
		tok := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kx-token", Namespace: attackerNS,
				Labels: map[string]string{tokenSecretLabel: tokenSecretValue},
			},
			Data: map[string][]byte{"token": []byte("machine-tok")},
		}

		objs := []client.Object{attacker, victim, tok}
		// Oversized peer list: 200 KeyorixSecrets sharing the token, each with a ref the
		// fetcher reports GONE — the mass-revocation probe must stay capped regardless.
		gone := map[string]bool{"gonex": true}
		for i := range 200 {
			name := "peer-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('0'+i%10))
			ref := "peerref-" + name
			gone[ref] = true
			objs = append(objs, &secretsv1alpha1.KeyorixSecret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: attackerNS, UID: types.UID(name)},
				Spec: secretsv1alpha1.KeyorixSecretSpec{
					Server:         "https://keyorix.internal",
					TokenSecretRef: secretsv1alpha1.SecretKeySelector{Name: "kx-token", Key: "token"},
					Data:           []secretsv1alpha1.KeyorixSecretData{{SecretKey: "k", Ref: ref}},
					PrunePolicy:    secretsv1alpha1.PrunePolicyDelete,
				},
			})
		}

		s := testScheme(t)
		inner := fake.NewClientBuilder().
			WithScheme(s).
			WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
			WithObjects(objs...).
			Build()

		c := interceptor.NewClient(inner, interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if e := hostileErr(d.next()); e != nil {
					return e
				}
				return cl.Get(ctx, key, obj, opts...)
			},
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if e := hostileErr(d.next()); e != nil {
					return e
				}
				return cl.List(ctx, list, opts...)
			},
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if e := hostileErr(d.next()); e != nil {
					return e
				}
				return cl.Update(ctx, obj, opts...)
			},
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if e := hostileErr(d.next()); e != nil {
					return e
				}
				return cl.Delete(ctx, obj, opts...)
			},
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if e := hostileErr(d.next()); e != nil {
					return e
				}
				return cl.Create(ctx, obj, opts...)
			},
		})

		fetcher := &countingFetcher{inner: &canaryFuzzFetcher{gone: gone}}
		rec := events.NewFakeRecorder(512)
		rr := &KeyorixSecretReconciler{
			Client:         c,
			Scheme:         s,
			AllowedServers: []string{"https://keyorix.internal"},
			newClient:      func(_, _ string) valueFetcher { return fetcher },
			hashKey:        []byte("fuzz-fixture-hmac-key"),
			Recorder:       rec,
		}

		_, rerr := rr.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "attacker", Namespace: attackerNS},
		})

		// (2) Bounded work.
		if n := fetcher.calls.Load(); n > int64(massPruneProbeCap)+8 {
			t.Fatalf("unbounded upstream fan-out: %d fetches for one reconcile (cap is massPruneProbeCap=%d + own data) — DoS amplifier", n, massPruneProbeCap)
		}

		// (3) Cross-tenant integrity: the victim Secret, if it still exists, is unchanged.
		// Read through the raw inner client so interceptor errors can't mask the check.
		var vic corev1.Secret
		if err := inner.Get(context.Background(), types.NamespacedName{Namespace: attackerNS, Name: victimSecret}, &vic); err == nil {
			if string(vic.Data[victimDataK]) != victimDataV || len(vic.Data) != 1 {
				t.Fatalf("victim Secret data was modified under hostile API responses: %v", vic.Data)
			}
		}

		// (4) Canary not leaked.
		var got secretsv1alpha1.KeyorixSecret
		if err := inner.Get(context.Background(), types.NamespacedName{Namespace: attackerNS, Name: "attacker"}, &got); err == nil {
			if blob, _ := json.Marshal(got.Status); strings.Contains(string(blob), canaryValue) {
				t.Fatalf("CANARY LEAK in .status under hostile API: %s", blob)
			}
		}
		if rerr != nil && strings.Contains(rerr.Error(), canaryValue) {
			t.Fatalf("CANARY LEAK in reconcile error under hostile API: %v", rerr)
		}
	drain:
		for {
			select {
			case ev := <-rec.Events:
				if strings.Contains(ev, canaryValue) {
					t.Fatalf("CANARY LEAK in Event under hostile API: %s", ev)
				}
			default:
				break drain
			}
		}
	})
}
