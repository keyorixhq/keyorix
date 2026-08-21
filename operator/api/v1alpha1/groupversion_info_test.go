package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToScheme_RegistersTypes(t *testing.T) {
	scheme := runtime.NewScheme()

	require.NoError(t, AddToScheme(scheme))

	assert.True(t, scheme.Recognizes(GroupVersion.WithKind("KeyorixSecret")),
		"AddToScheme must register KeyorixSecret under the secrets.keyorix.io/v1alpha1 group/version")
	assert.True(t, scheme.Recognizes(GroupVersion.WithKind("KeyorixSecretList")),
		"AddToScheme must register KeyorixSecretList under the secrets.keyorix.io/v1alpha1 group/version")

	// New must produce usable instances of the registered types.
	obj, err := scheme.New(GroupVersion.WithKind("KeyorixSecret"))
	require.NoError(t, err)
	_, ok := obj.(*KeyorixSecret)
	assert.True(t, ok, "scheme.New(KeyorixSecret) must return a *KeyorixSecret")

	listObj, err := scheme.New(GroupVersion.WithKind("KeyorixSecretList"))
	require.NoError(t, err)
	_, ok = listObj.(*KeyorixSecretList)
	assert.True(t, ok, "scheme.New(KeyorixSecretList) must return a *KeyorixSecretList")
}

func TestAddToScheme_RegistersListKindMetadata(t *testing.T) {
	// metav1.AddToGroupVersion (called from addKnownTypes) additionally registers the
	// generic List/ListOptions/etc. kinds for the group/version; assert one of those to
	// confirm that call actually ran, not just AddKnownTypes.
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))

	assert.True(t, scheme.Recognizes(GroupVersion.WithKind("ListOptions")),
		"metav1.AddToGroupVersion must register the generic ListOptions kind for this group/version")
}

func TestGroupVersion_Value(t *testing.T) {
	assert.Equal(t, "secrets.keyorix.io", GroupVersion.Group)
	assert.Equal(t, "v1alpha1", GroupVersion.Version)
}

func TestSchemeBuilder_AddToSchemeIsAddToScheme(t *testing.T) {
	// AddToScheme is assigned from SchemeBuilder.AddToScheme; assert it behaves the same
	// way a fresh call through SchemeBuilder would (guards against the var wiring rotting
	// silently if the package is ever refactored).
	scheme := runtime.NewScheme()
	require.NoError(t, SchemeBuilder.AddToScheme(scheme))
	assert.True(t, scheme.Recognizes(GroupVersion.WithKind("KeyorixSecret")))
}

func TestAddToScheme_ObjectKindsRoundTrip(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, AddToScheme(scheme))

	kinds, _, err := scheme.ObjectKinds(&KeyorixSecret{})
	require.NoError(t, err)
	require.Len(t, kinds, 1)
	assert.Equal(t, GroupVersion.WithKind("KeyorixSecret"), kinds[0])

	// Sanity: metav1.TypeMeta embedding didn't break normal object identification.
	ks := &KeyorixSecret{ObjectMeta: metav1.ObjectMeta{Name: "x"}}
	kinds, _, err = scheme.ObjectKinds(ks)
	require.NoError(t, err)
	assert.Equal(t, GroupVersion.WithKind("KeyorixSecret"), kinds[0])
}
