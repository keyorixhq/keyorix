package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/keyorixhq/keyorix/operator/internal/controller"
)

// secretByObject finds the corev1.Secret entry in a cache.Options.ByObject map. Map keys
// there are client.Object interface values (pointers), so a fresh &corev1.Secret{} lookup
// key never matches by identity — this looks the entry up by dynamic type instead.
func secretByObject(opts cache.Options) (cache.ByObject, bool) {
	for obj, byObj := range opts.ByObject {
		if _, ok := obj.(*corev1.Secret); ok {
			return byObj, true
		}
	}
	return cache.ByObject{}, false
}

// secretCacheOptions is the operator's #327 mitigation: without it, the manager's default
// cache backs Owns(&corev1.Secret{}) by listing/watching/caching EVERY Secret in the
// cluster in the operator's own process memory, even though the RBAC ClusterRole (required
// because this is a single cluster-wide operator instance, see cmd/main.go's doc comment)
// grants access far beyond what any one reconcile touches.
func TestSecretCacheOptions_ScopesInformerToManagedSecrets(t *testing.T) {
	cacheOpts, _ := secretCacheOptions()

	byObj, ok := secretByObject(cacheOpts)
	require.True(t, ok, "the Secret informer must have an explicit ByObject scope, not the cluster-wide default")
	require.NotNil(t, byObj.Label, "the Secret informer must be restricted by a label selector")

	// Only a Secret carrying the operator's managed-by label is cached...
	managed := labels.Set{controller.ManagedByLabel: controller.ManagedByValue}
	assert.True(t, byObj.Label.Matches(managed), "a Secret this operator manages must be cached (Owns() drift-detection depends on it)")

	// ...an arbitrary cluster Secret (e.g. an unrelated workload's Secret, or a
	// not-yet-adopted target Secret) must NOT be cached.
	unrelated := labels.Set{"app.kubernetes.io/name": "some-other-app"}
	assert.False(t, byObj.Label.Matches(unrelated), "a Secret this operator does not manage must not be cached")

	noLabels := labels.Set{}
	assert.False(t, byObj.Label.Matches(noLabels), "an unlabelled Secret (e.g. a token Secret) must not be cached")
}

// The label-restricted cache above must not make token Secrets (and not-yet-adopted target
// Secrets, which never carry the managed-by label) unreadable: direct client reads for
// Secrets must bypass that cache and go live to the API server instead.
func TestSecretCacheOptions_DisablesCacheForDirectSecretReads(t *testing.T) {
	_, clientOpts := secretCacheOptions()

	require.NotNil(t, clientOpts.Cache, "direct Secret reads must be excluded from the label-restricted cache")
	found := false
	for _, obj := range clientOpts.Cache.DisableFor {
		if _, ok := obj.(*corev1.Secret); ok {
			found = true
		}
	}
	assert.True(t, found, "corev1.Secret must be in Client.Cache.DisableFor so Get/List reads go live, not through the restricted cache")
}

// Guard against the cache options silently reverting to controller-runtime's cluster-wide
// default (a nil/empty ByObject map caches everything with no restriction at all).
func TestSecretCacheOptions_IsNotClusterWideDefault(t *testing.T) {
	cacheOpts, _ := secretCacheOptions()
	assert.NotEmpty(t, cacheOpts.ByObject, "cache.Options.ByObject must not be empty, or Secret caching silently reverts to the cluster-wide default")
}
