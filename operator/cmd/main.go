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

func main() {
	var metricsAddr, probeAddr, allowedServers string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address the metric endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address the probe endpoint binds to")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"enable leader election for controller manager (run a single active replica)")
	flag.StringVar(&allowedServers, "allowed-servers", os.Getenv("KEYORIX_ALLOWED_SERVERS"),
		"comma-separated list of trusted Keyorix base URLs (https://host) a KeyorixSecret's spec.server must match. "+
			"REQUIRED: without it every CR is rejected, so the operator never sends a token to a CR-chosen destination.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "keyorix-operator.secrets.keyorix.io",
		// #124: without this, the default cache watches/caches EVERY Secret in
		// every namespace the manager can reach — including every token Secret CR
		// authors reference, unrelated to this operator entirely. Scope the
		// shared informer cache to only Secrets this operator manages (the label
		// it always stamps on target Secrets in applySecret); Owns() still fires
		// correctly since our own target Secrets always carry the label. A token
		// Secret lookup goes through the manager's uncached APIReader instead
		// (wired into the reconciler below) — a one-off read has no reason to be
		// watched/cached at all.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {
					Label: labels.SelectorFromSet(labels.Set{controller.ManagedByLabel: controller.ManagedByValue}),
				},
			},
		},
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
