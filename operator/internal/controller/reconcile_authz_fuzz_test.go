package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/keyorix"
)

// canaryValue is the high-entropy marker planted as the fetched secret value. It must
// never surface anywhere a principal without Secret-read RBAC can see it: the CR
// .status, Kubernetes Events, or the reconcile's returned error. It legitimately DOES
// land in the target Secret's data — that is the whole job — so the target Secret is
// excluded from the leak scan.
const canaryValue = "kxCANARYv6Z7Q2m9X4w8R1t6Y3u5I0o7P2s4D6f8G1h3J5k7L9n0B2v4C6x8"

// canaryFuzzFetcher returns the canary as the value of every ref, unless the ref is
// classified (by the fuzzer) as gone / unauthorized / transiently-failing, in which
// case it returns the matching wrapped error. The error text embeds the ref (never the
// value), mirroring the real client, so the canary-in-error oracle is meaningful.
type canaryFuzzFetcher struct {
	gone   map[string]bool
	unauth map[string]bool
	fail   map[string]bool
}

func (f *canaryFuzzFetcher) FetchValue(_ context.Context, ref string) ([]byte, error) {
	switch {
	case f.gone[ref]:
		return nil, errGone(ref)
	case f.unauth[ref]:
		return nil, errUnauth(ref)
	case f.fail[ref]:
		return nil, errTransient(ref)
	}
	return []byte(canaryValue), nil
}

func errGone(ref string) error      { return wrapf(ref, keyorix.ErrSecretGone) }
func errUnauth(ref string) error    { return wrapf(ref, keyorix.ErrUnauthorized) }
func errTransient(ref string) error { return wrapf(ref, keyorix.ErrUnreachable) }

func wrapf(ref string, sentinel error) error {
	// %w so the controller's errors.Is classification still fires; ref, not value.
	return &wrappedRefErr{ref: ref, sentinel: sentinel}
}

type wrappedRefErr struct {
	ref      string
	sentinel error
}

func (e *wrappedRefErr) Error() string { return "fetch " + e.ref + " failed" }
func (e *wrappedRefErr) Unwrap() error { return e.sentinel }

// byteReader is a tiny deterministic consumer of fuzz bytes.
type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) u8() byte {
	if r.i >= len(r.b) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

// str reads a length-prefixed slice (length capped) and returns it as a string.
func (r *byteReader) str(maxLen int) string {
	n := int(r.u8())
	if maxLen > 0 && n > maxLen {
		n = maxLen
	}
	out := make([]byte, 0, n)
	for range n {
		out = append(out, r.u8())
	}
	return string(out)
}

const (
	attackerNS   = "tenant-a"
	attackerUID  = "attacker-uid-0001"
	victimUID    = "victim-uid-0002"
	victimSecret = "victim-secret"
	victimDataK  = "keep"
	victimDataV  = "VICTIM-DO-NOT-TOUCH"
)

// FuzzReconcileAuthzBoundary drives a full KeyorixSecret reconcile against a
// controller-runtime fake Kubernetes API, with the attacker-controlled fields of the CR
// (target.name, data refs/keys, prunePolicy, onSuspend, the confirm-prune annotation,
// the token key) and the upstream fetch outcome all derived from the fuzz input. The
// attacker holds only KeyorixSecret-create RBAC in namespace "tenant-a".
//
// Three co-tenants exist in the fake cluster: the attacker's own token Secret (labelled
// so the token gate passes) and a VICTIM Secret owned (controller ownerRef) by a
// different victim CR. The oracles:
//
//  1. NAMESPACE SCOPE — after the reconcile, every Secret anywhere in the cluster is in
//     "tenant-a". The reconciler must never materialise or touch a Secret in another
//     namespace (it only ever builds a NamespacedName from ks.Namespace).
//  2. CROSS-TENANT INTEGRITY — the victim Secret still exists and still holds exactly
//     its original data. applySecret/wipeTargetSecret/emptyManagedSecret must refuse to
//     overwrite, delete or empty a Secret this CR does not CONTROL (metav1.IsControlledBy),
//     even when the attacker sets spec.target.name = "victim-secret".
//  3. CANARY — the fetched secret value never appears in the CR .status (serialised),
//     in any Kubernetes Event, or in the reconcile's returned error string.
//  4. No panic, under any input.
//
// What this does NOT verify:
//   - It drives the reconciler BELOW CRD admission (direct fake-client objects), so it
//     does not prove the CRD schema (MaxItems, Pattern, listType=map) rejects a shape;
//     it proves the controller's own in-code defenses hold regardless of admission.
//   - It does not exercise the real network client, leader election, informer caching,
//     or real RBAC — only the reconcile logic.
//   - The canary scan covers status/events/error, not operator stdout logs (the
//     controller routes value-free messages through logr; no value is ever passed to a
//     logger in the reconcile path — a separate static claim, not re-proven here).
func FuzzReconcileAuthzBoundary(f *testing.F) {
	f.Add([]byte{})
	// Cross-tenant delete attack, correctly encoded for the decoder below:
	// target.name="victim-secret", one data entry secretKey="k" ref="gonex" that the
	// fetcher reports GONE, prunePolicy Delete, default token key, no confirm-prune ack.
	// This drives wipeAndFailGone(secretName="victim-secret"); the reconciler must still
	// NOT delete the victim's Secret (it is not IsControlledBy this CR). Oracle (2).
	f.Add([]byte{
		13, 118, 105, 99, 116, 105, 109, 45, 115, 101, 99, 114, 101, 116, // targetName="victim-secret"
		0,      // nEntries -> 1
		1, 107, // secretKey="k"
		5, 103, 111, 110, 101, 120, // ref="gonex"
		1, // outcome -> gone
		0, // prune -> Delete
		0, // onSuspend
		1, // tokenKey -> default "token"
		1, // annos -> no confirm-prune ack
	})
	// Same target but a healthy fetch (value = the canary) into target.name="victim-secret":
	// exercises applySecret's adopt-refusal (oracle 2 overwrite arm) and the
	// canary-into-status path (oracle 3).
	f.Add([]byte{
		13, 118, 105, 99, 116, 105, 109, 45, 115, 101, 99, 114, 101, 116,
		0,
		1, 107,
		5, 103, 111, 110, 101, 120,
		0, // outcome -> healthy value (the canary)
		0, 0, 1, 1,
	})
	// Benign target "my-target", healthy fetch (value = the canary): reaches the
	// success path and writes .status.syncedHash — the canary must NOT appear there
	// (it is HMAC-fingerprinted, #124). Oracle (3) status arm.
	f.Add([]byte{
		9, 109, 121, 45, 116, 97, 114, 103, 101, 116, // targetName="my-target"
		0,      // nEntries -> 1
		1, 107, // secretKey="k"
		5, 111, 107, 114, 101, 102, // ref="okref"
		0, // outcome -> healthy value (the canary)
		0, // prune
		0, // onSuspend
		1, // tokenKey default
		1, // no ack
	})
	f.Add([]byte{0x02, 5, 'd', 'b', '-', 'c', 'r', 0x03, 0x00})
	f.Add(bytes32(0xAA))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := &byteReader{b: data}

		targetName := r.str(64)
		nEntries := int(r.u8()%4) + 1 // 1..4 data entries
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

		// The victim Secret: managed-by label present (so the label check alone would
		// pass), but CONTROLLED by a different CR — only IsControlledBy separates them.
		victim := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: victimSecret, Namespace: attackerNS,
				Labels: map[string]string{ManagedByLabel: ManagedByValue},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: secretsv1alpha1.GroupVersion.String(),
					Kind:       "KeyorixSecret", Name: "victim-cr",
					UID: victimUID, Controller: boolptr(true),
				}},
			},
			Data: map[string][]byte{victimDataK: []byte(victimDataV)},
		}
		tok := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kx-token", Namespace: attackerNS,
				Labels: map[string]string{tokenSecretLabel: tokenSecretValue},
			},
			Data: map[string][]byte{"token": []byte("machine-tok"), tokenKey: []byte("machine-tok")},
		}

		s := testScheme(t)
		c := fake.NewClientBuilder().
			WithScheme(s).
			WithStatusSubresource(&secretsv1alpha1.KeyorixSecret{}).
			WithObjects(attacker, victim, tok).
			Build()
		rec := events.NewFakeRecorder(256)
		rr := &KeyorixSecretReconciler{
			Client:         c,
			Scheme:         s,
			AllowedServers: []string{"https://keyorix.internal"},
			newClient:      func(_, _ string) valueFetcher { return &canaryFuzzFetcher{gone: gone, unauth: unauth, fail: fail} },
			hashKey:        []byte("fuzz-fixture-hmac-key"),
			Recorder:       rec,
		}

		// (4) No panic.
		_, rerr := rr.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: "attacker", Namespace: attackerNS},
		})

		ctx := context.Background()

		// (1) Namespace scope: no Secret outside tenant-a exists.
		var all corev1.SecretList
		if err := c.List(ctx, &all); err != nil {
			t.Fatalf("list secrets: %v", err)
		}
		for i := range all.Items {
			if all.Items[i].Namespace != attackerNS {
				t.Fatalf("reconcile created/left a Secret outside the CR namespace: %s/%s — "+
					"cross-namespace write", all.Items[i].Namespace, all.Items[i].Name)
			}
		}

		// (2) Cross-tenant integrity: the victim Secret is untouched.
		var vic corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: attackerNS, Name: victimSecret}, &vic); err != nil {
			t.Fatalf("victim Secret was DELETED by the attacker's reconcile (target.name=%q, err=%v): %v — "+
				"cross-tenant delete via unowned Secret", targetName, rerr, err)
		}
		if string(vic.Data[victimDataK]) != victimDataV || len(vic.Data) != 1 {
			t.Fatalf("victim Secret data was MODIFIED by the attacker's reconcile (target.name=%q): got %v — "+
				"cross-tenant overwrite/clear via unowned Secret", targetName, vic.Data)
		}

		// (3) Canary: not in status, events, or returned error.
		var got secretsv1alpha1.KeyorixSecret
		if err := c.Get(ctx, types.NamespacedName{Namespace: attackerNS, Name: "attacker"}, &got); err == nil {
			blob, _ := json.Marshal(got.Status)
			if strings.Contains(string(blob), canaryValue) {
				t.Fatalf("CANARY LEAK: fetched secret value appears in CR .status: %s", blob)
			}
		}
		if rerr != nil && strings.Contains(rerr.Error(), canaryValue) {
			t.Fatalf("CANARY LEAK: fetched secret value appears in the reconcile error: %v", rerr)
		}
	drain:
		for {
			select {
			case ev := <-rec.Events:
				if strings.Contains(ev, canaryValue) {
					t.Fatalf("CANARY LEAK: fetched secret value appears in a Kubernetes Event: %s", ev)
				}
			default:
				break drain
			}
		}
	})
}

func bytes32(fill byte) []byte {
	b := make([]byte, 48)
	for i := range b {
		b[i] = fill
	}
	return b
}

func boolptr(b bool) *bool { return &b }
