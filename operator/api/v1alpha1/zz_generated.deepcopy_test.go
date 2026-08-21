package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// populatedKeyorixSecret builds a KeyorixSecret with every slice/pointer field
// filled in, so DeepCopy tests can catch a forgotten deep-copy of any of them
// (a shallow copy would let mutating the copy's slice/pointer fields bleed
// back into the original).
func populatedKeyorixSecret() *KeyorixSecret {
	refresh := metav1.Duration{Duration: 5 * time.Minute}
	lastSync := metav1.NewTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))

	return &KeyorixSecret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "KeyorixSecret",
			APIVersion: "secrets.keyorix.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
			Labels:    map[string]string{"team": "platform"},
		},
		Spec: KeyorixSecretSpec{
			Server: "https://keyorix.internal",
			TokenSecretRef: SecretKeySelector{
				Name: "token-secret",
				Key:  "token",
			},
			RefreshInterval: &refresh,
			Target: KeyorixSecretTarget{
				Name: "target-secret",
				Type: corev1.SecretTypeOpaque,
			},
			Data: []KeyorixSecretData{
				{SecretKey: "db-password", Ref: "proj/env/db-password"},
				{SecretKey: "api-key", Ref: "proj/env/api-key"},
			},
		},
		Status: KeyorixSecretStatus{
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Synced",
					Message:            "ok",
					LastTransitionTime: lastSync,
				},
			},
			LastSyncTime:       &lastSync,
			SyncedHash:         "abc123",
			ObservedGeneration: 3,
			LastTargetName:     "target-secret",
		},
	}
}

func TestKeyorixSecret_DeepCopy_IndependentOfOriginal(t *testing.T) {
	orig := populatedKeyorixSecret()
	cp := orig.DeepCopy()

	require.NotNil(t, cp)
	assert.Equal(t, orig, cp, "copy must be equal to the original right after copying")
	// Must not be the same object.
	assert.NotSame(t, orig, cp)

	// Mutate every slice/pointer field on the copy and assert the original is untouched.
	cp.ObjectMeta.Labels["team"] = "mutated"
	cp.Spec.RefreshInterval.Duration = 99 * time.Minute
	cp.Spec.Data[0].SecretKey = "mutated"
	cp.Spec.Data = append(cp.Spec.Data, KeyorixSecretData{SecretKey: "new", Ref: "new/new/new"})
	cp.Status.Conditions[0].Message = "mutated"
	cp.Status.LastSyncTime.Time = cp.Status.LastSyncTime.Time.Add(time.Hour)
	cp.Status.SyncedHash = "mutated"

	assert.Equal(t, "platform", orig.ObjectMeta.Labels["team"], "label map must be deep-copied")
	assert.Equal(t, 5*time.Minute, orig.Spec.RefreshInterval.Duration, "RefreshInterval pointer must be deep-copied")
	assert.Equal(t, "db-password", orig.Spec.Data[0].SecretKey, "Data slice elements must be deep-copied")
	assert.Len(t, orig.Spec.Data, 2, "appending to the copy's Data slice must not affect the original")
	assert.Equal(t, "ok", orig.Status.Conditions[0].Message, "Conditions slice elements must be deep-copied")
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), orig.Status.LastSyncTime.Time,
		"LastSyncTime pointer must be deep-copied")
	assert.Equal(t, "abc123", orig.Status.SyncedHash)
}

func TestKeyorixSecret_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecret
	assert.Nil(t, in.DeepCopy())
}

func TestKeyorixSecret_DeepCopyObject(t *testing.T) {
	orig := populatedKeyorixSecret()
	obj := orig.DeepCopyObject()

	require.NotNil(t, obj)
	cp, ok := obj.(*KeyorixSecret)
	require.True(t, ok, "DeepCopyObject must return a *KeyorixSecret usable via type assertion")
	assert.Equal(t, orig, cp)
}

func TestKeyorixSecret_DeepCopyInto_ZeroValue_NoPanic(t *testing.T) {
	in := &KeyorixSecret{}
	out := &KeyorixSecret{}
	assert.NotPanics(t, func() {
		in.DeepCopyInto(out)
	})
	assert.Equal(t, in, out)
	assert.Nil(t, out.Spec.RefreshInterval)
	assert.Nil(t, out.Status.LastSyncTime)
	assert.Nil(t, out.Spec.Data)
	assert.Nil(t, out.Status.Conditions)
}

func TestKeyorixSecretList_DeepCopy_IndependentOfOriginal(t *testing.T) {
	orig := &KeyorixSecretList{
		TypeMeta: metav1.TypeMeta{Kind: "KeyorixSecretList", APIVersion: "secrets.keyorix.io/v1alpha1"},
		ListMeta: metav1.ListMeta{ResourceVersion: "1"},
		Items: []KeyorixSecret{
			*populatedKeyorixSecret(),
			*populatedKeyorixSecret(),
		},
	}
	orig.Items[1].Name = "second-secret"

	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)
	assert.NotSame(t, orig, cp)

	// Mutate the copy's items and nested fields; original must be unaffected.
	cp.Items[0].Spec.Data[0].SecretKey = "mutated"
	cp.Items = append(cp.Items, KeyorixSecret{})

	assert.Equal(t, "db-password", orig.Items[0].Spec.Data[0].SecretKey,
		"List.Items elements must be deep-copied, not just slice-copied")
	assert.Len(t, orig.Items, 2, "appending to the copy's Items slice must not affect the original")
}

func TestKeyorixSecretList_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecretList
	assert.Nil(t, in.DeepCopy())
}

func TestKeyorixSecretList_DeepCopy_NilItems_NoPanic(t *testing.T) {
	in := &KeyorixSecretList{}
	var out *KeyorixSecretList
	assert.NotPanics(t, func() {
		out = in.DeepCopy()
	})
	assert.Nil(t, out.Items)
}

func TestKeyorixSecretList_DeepCopyObject(t *testing.T) {
	orig := &KeyorixSecretList{Items: []KeyorixSecret{*populatedKeyorixSecret()}}
	obj := orig.DeepCopyObject()

	require.NotNil(t, obj)
	cp, ok := obj.(*KeyorixSecretList)
	require.True(t, ok, "DeepCopyObject must return a *KeyorixSecretList usable via type assertion")
	assert.Equal(t, orig, cp)
}

func TestKeyorixSecret_DeepCopyObject_NilReceiver(t *testing.T) {
	var in *KeyorixSecret
	assert.Nil(t, in.DeepCopyObject(), "DeepCopyObject on a nil receiver must return a true nil runtime.Object")
}

func TestKeyorixSecretList_DeepCopyObject_NilReceiver(t *testing.T) {
	var in *KeyorixSecretList
	assert.Nil(t, in.DeepCopyObject(), "DeepCopyObject on a nil receiver must return a true nil runtime.Object")
}

func TestKeyorixSecretSpec_DeepCopy_IndependentOfOriginal(t *testing.T) {
	refresh := metav1.Duration{Duration: time.Minute}
	orig := &KeyorixSecretSpec{
		Server:          "https://keyorix.internal",
		TokenSecretRef:  SecretKeySelector{Name: "token-secret", Key: "token"},
		RefreshInterval: &refresh,
		Target:          KeyorixSecretTarget{Name: "t", Type: corev1.SecretTypeOpaque},
		Data:            []KeyorixSecretData{{SecretKey: "a", Ref: "p/e/a"}},
	}
	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)

	cp.RefreshInterval.Duration = time.Hour
	cp.Data[0].SecretKey = "mutated"

	assert.Equal(t, time.Minute, orig.RefreshInterval.Duration)
	assert.Equal(t, "a", orig.Data[0].SecretKey)
}

func TestKeyorixSecretSpec_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecretSpec
	assert.Nil(t, in.DeepCopy())
}

func TestKeyorixSecretSpec_DeepCopyInto_NilOptionalFields_NoPanic(t *testing.T) {
	in := &KeyorixSecretSpec{Server: "https://x"}
	out := &KeyorixSecretSpec{}
	assert.NotPanics(t, func() {
		in.DeepCopyInto(out)
	})
	assert.Nil(t, out.RefreshInterval)
	assert.Nil(t, out.Data)
}

func TestKeyorixSecretStatus_DeepCopy_IndependentOfOriginal(t *testing.T) {
	lastSync := metav1.NewTime(time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC))
	orig := &KeyorixSecretStatus{
		Conditions:         []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Synced", Message: "ok"}},
		LastSyncTime:       &lastSync,
		SyncedHash:         "hash",
		ObservedGeneration: 1,
		LastTargetName:     "name",
	}
	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)

	cp.Conditions[0].Message = "mutated"
	cp.LastSyncTime.Time = cp.LastSyncTime.Time.Add(time.Hour)

	assert.Equal(t, "ok", orig.Conditions[0].Message)
	assert.Equal(t, time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC), orig.LastSyncTime.Time)
}

func TestKeyorixSecretStatus_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecretStatus
	assert.Nil(t, in.DeepCopy())
}

func TestKeyorixSecretStatus_DeepCopyInto_NilOptionalFields_NoPanic(t *testing.T) {
	in := &KeyorixSecretStatus{}
	out := &KeyorixSecretStatus{}
	assert.NotPanics(t, func() {
		in.DeepCopyInto(out)
	})
	assert.Nil(t, out.Conditions)
	assert.Nil(t, out.LastSyncTime)
}

func TestKeyorixSecretTarget_DeepCopy(t *testing.T) {
	orig := &KeyorixSecretTarget{Name: "t", Type: corev1.SecretTypeOpaque}
	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)
	assert.NotSame(t, orig, cp)

	cp.Name = "mutated"
	assert.Equal(t, "t", orig.Name)
}

func TestKeyorixSecretTarget_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecretTarget
	assert.Nil(t, in.DeepCopy())
}

func TestKeyorixSecretData_DeepCopy(t *testing.T) {
	orig := &KeyorixSecretData{SecretKey: "k", Ref: "p/e/k"}
	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)
	assert.NotSame(t, orig, cp)

	cp.SecretKey = "mutated"
	assert.Equal(t, "k", orig.SecretKey)
}

func TestKeyorixSecretData_DeepCopy_Nil(t *testing.T) {
	var in *KeyorixSecretData
	assert.Nil(t, in.DeepCopy())
}

func TestSecretKeySelector_DeepCopy(t *testing.T) {
	orig := &SecretKeySelector{Name: "s", Key: "k"}
	cp := orig.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, orig, cp)
	assert.NotSame(t, orig, cp)

	cp.Key = "mutated"
	assert.Equal(t, "k", orig.Key)
}

func TestSecretKeySelector_DeepCopy_Nil(t *testing.T) {
	var in *SecretKeySelector
	assert.Nil(t, in.DeepCopy())
}
