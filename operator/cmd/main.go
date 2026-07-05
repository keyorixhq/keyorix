// Command keyorix-operator runs the KeyorixSecret controller: it reconciles
// KeyorixSecret resources into native Kubernetes Secrets and keeps them current.
package main

import (
	"flag"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	secretsv1alpha1 "github.com/keyorixhq/keyorix/operator/api/v1alpha1"
	"github.com/keyorixhq/keyorix/operator/internal/controller"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1alpha1.AddToScheme(scheme))
}

// secretCacheOptions scopes the manager's Secret informer to only Secrets the operator
// itself manages, and routes every other Secret read straight to the API server instead
// of through that (now-restricted) cache.
//
// By DEFAULT the operator is deployed as a single cluster-wide instance: it watches
// KeyorixSecret CRs (a namespaced CRD) across every namespace, so its ClusterRole
// necessarily grants Secret get/list/watch/create/update/patch/delete cluster-wide too —
// with no static namespace list configured, the operator genuinely cannot predict which
// namespace the next CR (and its TokenSecretRef/target Secret) will land in, and
// Kubernetes RBAC has no way to scope list/watch by resourceNames or to a dynamically
// changing namespace set. See #327/#427 and operator/config/rbac/role.yaml /
// deploy/helm/keyorix-operator/templates/rbac.yaml for the fuller writeup.
//
// Operators who instead run one instance PER namespace (or per bounded tenant set) can
// opt into the -watch-namespaces flag: it restricts every cached type (KeyorixSecret CRs
// AND Secrets) to just those namespaces via cache.Options.DefaultNamespaces, and the Helm
// chart's watchNamespaces value correspondingly swaps the cluster-wide ClusterRoleBinding
// for a namespace-scoped RoleBinding per watched namespace (still against the same
// ClusterRole definition, for manifest reusability) — the least-privilege choice for that
// deployment model, without forcing it on the default multi-tenant one.
//
// What IS always avoidable, regardless of namespace scoping, is controller-runtime's
// default behavior of caching every Secret in the cluster in the operator's own process
// memory just because SetupWithManager calls Owns(&corev1.Secret{}) to watch the Secrets
// it owns. That default cache would hold the full contents of every Secret it can see —
// including ones this operator has no relationship to — turning a compromise of the
// operator process (e.g. the SSRF/dependency findings #184/#240) into a trivial in-memory
// dump of Secrets instead of just the ones it manages. Restricting the informer to
// controller.ManagedByLabel closes that gap: only Secrets this operator previously created
// (and therefore already has full read/write RBAC over anyway) are ever resident in its
// cache.
//
// Token Secrets (read via TokenSecretRef) and not-yet-adopted target Secrets never carry
// that label, so DisableFor routes their reads around the label-restricted cache to a live
// API call — they stay correctly readable on every reconcile, just uncached.
func secretCacheOptions(watchNamespaces []string) (cache.Options, client.Options) {
	managedByThisOperator := labels.SelectorFromSet(map[string]string{
		controller.ManagedByLabel: controller.ManagedByValue,
	})
	opts := cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Label: managedByThisOperator},
		},
	}
	if len(watchNamespaces) > 0 {
		defaultNamespaces := make(map[string]cache.Config, len(watchNamespaces))
		for _, ns := range watchNamespaces {
			defaultNamespaces[ns] = cache.Config{}
		}
		// Left unset on the Secret ByObject entry above so it defaults from
		// DefaultNamespaces (controller-runtime's precedence rule): the label
		// restriction and the namespace restriction combine, rather than one
		// overriding the other.
		opts.DefaultNamespaces = defaultNamespaces
	}
	return opts, client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.Secret{}},
		},
	}
}

func main() {
	var metricsAddr, probeAddr, allowedServers, watchNamespaces string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address the metric endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address the probe endpoint binds to")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"enable leader election for controller manager (run a single active replica)")
	flag.StringVar(&allowedServers, "allowed-servers", os.Getenv("KEYORIX_ALLOWED_SERVERS"),
		"comma-separated list of trusted Keyorix base URLs (https://host) a KeyorixSecret's spec.server must match. "+
			"REQUIRED: without it every CR is rejected, so the operator never sends a token to a CR-chosen destination.")
	flag.StringVar(&watchNamespaces, "watch-namespaces", os.Getenv("KEYORIX_WATCH_NAMESPACES"),
		"OPTIONAL comma-separated list of namespaces this instance manages KeyorixSecret CRs and their target "+
			"Secrets in. Leave empty (the default) to watch every namespace in the cluster, which requires a "+
			"cluster-wide RBAC grant (#327/#427). Set this to run one operator instance per namespace/tenant set "+
			"with a namespace-scoped RBAC grant instead — see deploy/helm/keyorix-operator's watchNamespaces value.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	var watchNS []string
	for _, ns := range strings.Split(watchNamespaces, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			watchNS = append(watchNS, ns)
		}
	}
	if len(watchNS) > 0 {
		setupLog.Info("restricting watched namespaces", "namespaces", watchNS)
	}

	secretCache, secretClient := secretCacheOptions(watchNS)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "keyorix-operator.secrets.keyorix.io",
		// Bound the blast radius of the cluster-wide Secret RBAC this operator must hold
		// (see secretCacheOptions and #327/#124): don't cache every Secret in the cluster,
		// only ones this operator manages.
		Cache:  secretCache,
		Client: secretClient,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var allowed []string
	for _, s := range strings.Split(allowedServers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			allowed = append(allowed, s)
		}
	}
	if len(allowed) == 0 {
		setupLog.Info("WARNING: --allowed-servers is not set; every KeyorixSecret will be REJECTED until you configure the trusted Keyorix server URL(s)")
	}
	reconciler, err := controller.NewReconciler(mgr.GetClient(), mgr.GetScheme(), mgr.GetAPIReader(), allowed)
	if err != nil {
		setupLog.Error(err, "unable to initialize controller", "controller", "KeyorixSecret")
		os.Exit(1)
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KeyorixSecret")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting keyorix-operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
