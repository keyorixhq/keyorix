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
// cluster in the operator's own process memory, even though a cluster-wide-mode RBAC
// ClusterRole (see cmd/main.go's doc comment and ADR-076) grants access far beyond what any
// one reconcile touches.
func TestSecretCacheOptions_ScopesInformerToManagedSecrets(t *testing.T) {
	cacheOpts, _ := secretCacheOptions(namespaceScope{allNamespaces: true})

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
	_, clientOpts := secretCacheOptions(namespaceScope{allNamespaces: true})

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
	cacheOpts, _ := secretCacheOptions(namespaceScope{allNamespaces: true})
	assert.NotEmpty(t, cacheOpts.ByObject, "cache.Options.ByObject must not be empty, or Secret caching silently reverts to the cluster-wide default")
}

// #327/#427: when the operator is configured (via -watch-namespaces, wired from the Helm
// chart's watchNamespaces value) to manage only a bounded set of namespaces, the manager's
// cache — and therefore, in practice via the corresponding RBAC RoleBinding, its real
// access — must be limited to exactly those namespaces, not silently fall back to
// cluster-wide.
func TestSecretCacheOptions_RestrictsToWatchNamespacesWhenSet(t *testing.T) {
	cacheOpts, _ := secretCacheOptions(namespaceScope{namespaces: []string{"team-a", "team-b"}})

	require.NotNil(t, cacheOpts.DefaultNamespaces, "DefaultNamespaces must be set when watch namespaces are configured")
	assert.Len(t, cacheOpts.DefaultNamespaces, 2)
	_, hasA := cacheOpts.DefaultNamespaces["team-a"]
	_, hasB := cacheOpts.DefaultNamespaces["team-b"]
	assert.True(t, hasA)
	assert.True(t, hasB)

	// The label restriction on Secrets must still apply — namespace-scoping and
	// label-scoping combine rather than one replacing the other.
	byObj, ok := secretByObject(cacheOpts)
	require.True(t, ok)
	managed := labels.Set{controller.ManagedByLabel: controller.ManagedByValue}
	assert.True(t, byObj.Label.Matches(managed))
}

// ADR-076: -all-namespaces is the ONLY path that leaves DefaultNamespaces unset (which
// controller-runtime treats as cluster-wide, via its own len(DefaultNamespaces) > 0 check).
// Superseded TestSecretCacheOptions_DefaultsToClusterWideWhenUnset, which asserted the
// pre-ADR-076 behavior (nil/unset input defaulted to cluster-wide) that this ADR removes —
// namespaceScope has no "unset" input shape anymore; resolveScope is what used to own that
// default, and it no longer produces cluster-wide without an explicit -all-namespaces flag
// (see TestResolveScope_* below).
func TestSecretCacheOptions_AllNamespacesLeavesDefaultNamespacesUnset(t *testing.T) {
	cacheOpts, _ := secretCacheOptions(namespaceScope{allNamespaces: true})
	assert.Empty(t, cacheOpts.DefaultNamespaces, "DefaultNamespaces must stay unset for an explicit -all-namespaces scope")
}

// ADR-076's fail-closed contract: with neither -watch-namespaces nor -all-namespaces set,
// the operator watches only its own namespace, read from POD_NAMESPACE — never
// all-namespaces. This is the specific case the ADR calls out as needing direct test
// coverage: the Helm chart's default render always passes an explicit
// -watch-namespaces={{ .Release.Namespace }} flag (see deploy/helm/keyorix-operator), so a
// real deployment never actually exercises this fallback path — only a direct unit test
// does.
func TestResolveScope_DefaultsToPodNamespaceWhenNeitherFlagSet(t *testing.T) {
	scope, err := resolveScope("", false, "foo")
	require.NoError(t, err)
	assert.False(t, scope.allNamespaces)
	assert.Equal(t, []string{"foo"}, scope.namespaces)

	// End-to-end through secretCacheOptions too, matching what main() actually does with
	// the resolved scope: the cache must be scoped to "foo" only, nothing broader.
	cacheOpts, _ := secretCacheOptions(scope)
	require.NotNil(t, cacheOpts.DefaultNamespaces)
	assert.Len(t, cacheOpts.DefaultNamespaces, 1)
	_, hasFoo := cacheOpts.DefaultNamespaces["foo"]
	assert.True(t, hasFoo)
}

// ADR-076: an empty or unset POD_NAMESPACE with neither flag set must be a startup
// validation error naming POD_NAMESPACE, not a silent fallback to all-namespaces —
// controller-runtime treats an empty-string DefaultNamespaces key as cache.AllNamespaces, so
// passing an unvalidated blank POD_NAMESPACE through would silently produce a cluster-wide
// watch via code that reads as correctly scoped. main() treats this error as fatal
// (setupLog.Error + os.Exit(1)); this test proves the condition that drives that exit, which
// is the level main.go's own one-line error branch is actually worth testing at.
func TestResolveScope_EmptyPodNamespaceFailsClosed(t *testing.T) {
	_, err := resolveScope("", false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "POD_NAMESPACE")

	_, err = resolveScope("", false, "   ")
	require.Error(t, err, "a whitespace-only POD_NAMESPACE must also fail closed, not resolve to a blank namespace")
}

// ADR-076: -watch-namespaces and -all-namespaces are mutually exclusive, rejected outright
// rather than resolved by precedence — #1224 already showed precedence-based resolution of
// contradictory config is exactly how this class of bug produces a silent misrender.
func TestResolveScope_BothFlagsSetIsAnError(t *testing.T) {
	_, err := resolveScope("team-a,team-b", true, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// -watch-namespaces set (without -all-namespaces) takes the explicit list, regardless of
// POD_NAMESPACE — the flag is authoritative over the pod's own namespace when set.
func TestResolveScope_WatchNamespacesSetIgnoresPodNamespace(t *testing.T) {
	scope, err := resolveScope("team-a, team-b", false, "some-other-namespace")
	require.NoError(t, err)
	assert.False(t, scope.allNamespaces)
	assert.Equal(t, []string{"team-a", "team-b"}, scope.namespaces)
}

// -all-namespaces set (without -watch-namespaces) resolves to allNamespaces regardless of
// POD_NAMESPACE, and ignores an empty POD_NAMESPACE too — the flag is authoritative.
func TestResolveScope_AllNamespacesSetIgnoresPodNamespace(t *testing.T) {
	scope, err := resolveScope("", true, "")
	require.NoError(t, err)
	assert.True(t, scope.allNamespaces)
	assert.Empty(t, scope.namespaces)
}
