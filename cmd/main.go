/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	vaultv1alpha1 "github.com/panteparak/vault-access-operator/api/v1alpha1"
	"github.com/panteparak/vault-access-operator/features/connection"
	"github.com/panteparak/vault-access-operator/features/discovery"
	"github.com/panteparak/vault-access-operator/features/kvsecret"
	"github.com/panteparak/vault-access-operator/features/policy"
	"github.com/panteparak/vault-access-operator/features/role"
	vaultwebhook "github.com/panteparak/vault-access-operator/internal/webhook"
	"github.com/panteparak/vault-access-operator/pkg/cleanup"
	"github.com/panteparak/vault-access-operator/pkg/orphan"
	"github.com/panteparak/vault-access-operator/shared/controller/base"
	"github.com/panteparak/vault-access-operator/shared/events"
	"github.com/panteparak/vault-access-operator/shared/markers"
	"github.com/panteparak/vault-access-operator/shared/naming"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// clusterNamePattern restricts --cluster-name to characters safe in a Vault
// policy name and KV path segment (it becomes a prefix on both).
const clusterNamePattern = `^[a-zA-Z0-9._-]+$`

var clusterNameRE = regexp.MustCompile(clusterNamePattern)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(vaultv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var enableWebhooks bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", false,
		"If set, admission webhooks will be enabled. Requires webhook certificates to be configured.")
	var watchNamespacesFlag string
	flag.StringVar(&watchNamespacesFlag, "watch-namespaces", "",
		"Comma-separated list of namespaces the operator should watch. "+
			"Empty (default) watches all namespaces. Cluster-scoped CRDs "+
			"(VaultClusterPolicy, VaultClusterRole) are always watched regardless. "+
			"IMPROVEMENTS Missing Features §A.")
	var clusterName string
	flag.StringVar(&clusterName, "cluster-name", os.Getenv("CLUSTER_NAME"),
		"Per-cluster prefix applied to every Vault resource name (policies, roles), so multiple "+
			"operators sharing one Vault CE server derive non-colliding names. "+
			"Empty (default) disables prefixing. Must match "+clusterNamePattern+".")
	var managedMarkers bool
	flag.BoolVar(&managedMarkers, "managed-markers", os.Getenv("MANAGED_MARKERS") == "true",
		"Enable in-band ownership tracking (ADR 0008): conflict/adoption detection, discovery, and "+
			"orphan detection. Ownership travels ON the managed objects themselves (policy comment "+
			"header, KV custom_metadata) keyed to the connection's auth mount — no extra Vault grant "+
			"is required. Disabled by default (opt-in).")
	// Default is controller-runtime's production config (JSON encoder, info
	// level) so log fields are queryable in aggregators. Local/dev runs pass
	// --zap-devel for human-readable console output.
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if clusterName != "" && !clusterNameRE.MatchString(clusterName) {
		setupLog.Error(nil, "invalid --cluster-name; must match "+clusterNamePattern,
			"clusterName", clusterName)
		os.Exit(1)
	}
	naming.SetCluster(clusterName)
	markers.SetEnabled(managedMarkers)
	if !managedMarkers {
		setupLog.Info("managed-marker tracking disabled (opt-in via --managed-markers): " +
			"ownership/conflict detection, discovery, and orphan detection are inactive")
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

	// Initialize webhook server only if webhooks are enabled
	var webhookServer webhook.Server
	if enableWebhooks {
		// Initial webhook TLS options
		webhookTLSOpts := tlsOpts

		if len(webhookCertPath) > 0 {
			setupLog.Info("Initializing webhook certificate watcher using provided certificates",
				"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

			var err error
			webhookCertWatcher, err = certwatcher.New(
				filepath.Join(webhookCertPath, webhookCertName),
				filepath.Join(webhookCertPath, webhookCertKey),
			)
			if err != nil {
				setupLog.Error(err, "Failed to initialize webhook certificate watcher")
				os.Exit(1)
			}

			webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
				config.GetCertificate = webhookCertWatcher.GetCertificate
			})
		}

		webhookServer = webhook.NewServer(webhook.Options{
			TLSOpts: webhookTLSOpts,
		})
		setupLog.Info("Webhooks enabled")
	} else {
		setupLog.Info("Webhooks disabled")
	}

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient
	// for development and testing, this setup is not recommended for production.
	//
	// Production deployment: use the Helm chart at charts/vault-access-operator.
	// It wires cert-manager via `certManager.enabled=true` and mounts the
	// generated certs at the paths passed to --metrics-cert-path /
	// --webhook-cert-path. The `config/` kustomize bases are retained only as
	// a reference for `make deploy` and are not the supported install path.
	// (IMPROVEMENTS §25 — replaced an orphan TODO that had drifted out of
	// sync with the Helm chart.)
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {
			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	// GracefulShutdownTimeout (IMPROVEMENTS §32): cap the time the manager spends
	// draining in-flight reconciles after SIGTERM. Previously unset, which left
	// controller-runtime's default (30s). Vault bootstrap and long auth flows
	// can exceed 30s, so in-flight state was silently truncated on termination.
	// 2 minutes is a compromise: enough headroom for the slowest reconcile we've
	// seen in production, less than the Helm chart's terminationGracePeriodSeconds.
	gracefulShutdown := 2 * time.Minute

	// Build cache.Options for --watch-namespaces (IMPROVEMENTS §A). When
	// the flag is empty the cache watches every namespace (default). When
	// it's a comma-separated list, the cache is scoped to just those
	// namespaces — useful for large multi-tenant clusters where one
	// operator deployment serves a subset of the workloads.
	cacheOpts := cache.Options{}
	if watchNamespacesFlag != "" {
		namespaces := strings.Split(watchNamespacesFlag, ",")
		cacheOpts.DefaultNamespaces = make(map[string]cache.Config, len(namespaces))
		for _, ns := range namespaces {
			ns = strings.TrimSpace(ns)
			if ns == "" {
				continue
			}
			cacheOpts.DefaultNamespaces[ns] = cache.Config{}
		}
		setupLog.Info("cache scoped to namespaces",
			"namespaces", cacheOpts.DefaultNamespaces)
	}

	// Scope the ConfigMap informer to the operator's own namespace. The only
	// ConfigMap the operator touches is `vault-cleanup-queue` in its own ns
	// (see pkg/cleanup/queue.go). Without this override, controller-runtime
	// starts a cluster-wide ConfigMap list-watch, which fails with a
	// forbidden error (RBAC only grants ConfigMap perms on the operator ns)
	// and blocks the informer cache from ever syncing — the manager then
	// fails healthz and no reconciles run.
	operatorNamespace := resolveOperatorNamespace()
	cacheOpts.ByObject = map[client.Object]cache.ByObject{
		&corev1.ConfigMap{}: {
			Namespaces: map[string]cache.Config{
				operatorNamespace: {},
			},
		},
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsServerOptions,
		WebhookServer:           webhookServer,
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "2bf9394e.platform.io",
		GracefulShutdownTimeout: &gracefulShutdown,
		Cache:                   cacheOpts,
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Initialize the shared event bus for inter-feature communication
	eventBus := events.NewEventBus(setupLog.WithName("eventbus"))
	setupLog.Info("Initialized event bus")

	// Create Kubernetes clientset for TokenRequest API
	restConfig := ctrl.GetConfigOrDie()
	k8sClientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		setupLog.Error(err, "unable to create kubernetes clientset")
		os.Exit(1)
	}
	setupLog.Info("Created Kubernetes clientset for TokenRequest API")

	// Initialize features using Feature-Driven Design
	// Each feature is a self-contained vertical slice with its own controller, handler, and domain logic
	//
	// The four `mgr.GetEventRecorderFor(...) //nolint:staticcheck` below use the v1 events
	// API (k8s.io/client-go/tools/record). controller-runtime v0.23 deprecated this in favor
	// of GetEventRecorder, which returns a v1beta1 events.EventRecorder with a different
	// signature (requires `regarding`, `related`, `action`, `note`). Migrating is a
	// cross-cutting API change affecting every Event/Eventf call site, so we've deferred it.
	// See IMPROVEMENTS.md §24 for the full rationale.

	// Connection feature manages VaultConnection resources and provides the shared ClientCache
	connFeature := connection.New(connection.Config{
		EventBus:     eventBus,
		K8sClient:    mgr.GetClient(),
		K8sClientset: k8sClientset,
		Scheme:       mgr.GetScheme(),
		Log:          setupLog,
		Recorder:     mgr.GetEventRecorderFor("vaultconnection-controller"), //nolint:staticcheck
	})
	if err := connFeature.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to setup feature", "feature", "Connection")
		os.Exit(1)
	}
	setupLog.Info("Setup Connection feature")

	// Register the token reviewer rotator (IMPROVEMENTS §1). It refreshes each
	// connection's token_reviewer_jwt before it expires so Vault can keep calling
	// the Kubernetes TokenReview API on long-running deployments (without it,
	// K8s auth silently breaks ~1h after the mount is configured). Leader-gated
	// so only one replica rotates. Nil when no K8sClientset is configured.
	if connFeature.ReviewerController != nil {
		if err := mgr.Add(connFeature.ReviewerController); err != nil {
			setupLog.Error(err, "unable to register token reviewer controller with manager")
			os.Exit(1)
		}
		setupLog.Info("Registered token reviewer controller (leader-gated)")
	}

	// Policy feature manages VaultPolicy and VaultClusterPolicy resources
	policyFeature := policy.New(
		eventBus,
		connFeature.ClientCache,
		mgr.GetClient(),
		mgr.GetScheme(),
		setupLog,
		mgr.GetEventRecorderFor("vaultpolicy-controller"), //nolint:staticcheck
	)
	if err := policyFeature.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to setup feature", "feature", "Policy")
		os.Exit(1)
	}
	setupLog.Info("Setup Policy feature")

	// Role feature manages VaultRole and VaultClusterRole resources
	roleFeature := role.New(
		eventBus,
		connFeature.ClientCache,
		mgr.GetClient(),
		mgr.GetScheme(),
		setupLog,
		mgr.GetEventRecorderFor("vaultrole-controller"), //nolint:staticcheck
	)
	if err := roleFeature.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to setup feature", "feature", "Role")
		os.Exit(1)
	}
	setupLog.Info("Setup Role feature")

	// KVSecret feature seeds empty KV v2 secret paths (VaultKVSecret) so consumers
	// like External Secrets Operator don't fail on a missing source path.
	kvSecretFeature := kvsecret.New(
		connFeature.ClientCache,
		mgr.GetClient(),
		mgr.GetScheme(),
		setupLog,
		mgr.GetEventRecorderFor("vaultkvsecret-controller"), //nolint:staticcheck
	)
	if err := kvSecretFeature.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to setup feature", "feature", "KVSecret")
		os.Exit(1)
	}
	setupLog.Info("Setup KVSecret feature")

	// Discovery + orphan detection depend on managed markers (they scan the
	// marker KV path); only register them when marker tracking is enabled.
	if markers.Enabled() {
		// Discovery feature scans Vault for unmanaged resources
		discoveryFeature := discovery.New(discovery.Config{
			K8sClient:   mgr.GetClient(),
			Scheme:      mgr.GetScheme(),
			ClientCache: connFeature.ClientCache,
			Log:         setupLog,
			Recorder:    mgr.GetEventRecorderFor("discovery-controller"), //nolint:staticcheck
		})
		if err := discoveryFeature.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to setup feature", "feature", "Discovery")
			os.Exit(1)
		}
		setupLog.Info("Setup Discovery feature")
	}

	// Register the cleanup retry controller (IMPROVEMENTS §1). It drains items
	// that CleanupWorkflow enqueues when a Vault delete fails at finalizer time;
	// this prevents the silent-resource-leak bug tracked in IMPROVEMENTS §2.
	// The controller is leader-gated (NeedsLeaderElection=true) so only one
	// replica writes to the queue ConfigMap.
	// operatorNamespace is resolved earlier (before NewManager) so cacheOpts
	// can scope the ConfigMap informer to this namespace.
	cleanupQueue := cleanup.NewQueue(mgr.GetClient(), operatorNamespace)
	// OPERATOR_CLEANUP_RETRY_INTERVAL lets operators (and e2e tests) shorten
	// the 5-minute default retry cadence when that's too slow. Tests with
	// 10-minute drain assertions need the controller to tick at least twice
	// inside that window to give queued items a chance to succeed.
	cleanupRetryInterval := base.ParseIntervalEnv(
		"OPERATOR_CLEANUP_RETRY_INTERVAL", cleanup.DefaultRetryInterval, os.Stderr)
	cleanupCtrl := cleanup.NewController(cleanup.ControllerConfig{
		Queue:       cleanupQueue,
		ClientCache: cleanup.NewClientCacheAdapter(connFeature.ClientCache),
		Interval:    cleanupRetryInterval,
		Log:         setupLog.WithName("cleanup"),
	})
	if err := mgr.Add(cleanupCtrl); err != nil {
		setupLog.Error(err, "unable to register cleanup controller with manager")
		os.Exit(1)
	}
	setupLog.Info("Registered cleanup controller (leader-gated)")

	// Wire the queue into policy + role cleanup workflows so failed Vault
	// deletes enqueue for retry instead of leaking (IMPROVEMENTS §2). Must run
	// before SetupWithManager (already called above) — the handler setter
	// only mutates the pre-configured CleanupWorkflow, not an in-flight one,
	// and controllers haven't started yet because mgr.Start hasn't been called.
	policyFeature.WithCleanupQueue(cleanupQueue)
	roleFeature.WithCleanupQueue(cleanupQueue)

	// Register the orphan detection controller (IMPROVEMENTS §1). It periodically
	// scans Vault for resources carrying a managed-marker whose K8s owner is gone
	// and emits metrics. Leader-gated for the same reasons as cleanup. Only runs
	// when managed-marker tracking is enabled.
	if markers.Enabled() {
		orphanCtrl := orphan.NewController(orphan.ControllerConfig{
			K8sClient:   mgr.GetClient(),
			ClientCache: connFeature.ClientCache,
			Log:         setupLog.WithName("orphan"),
		})
		if err := mgr.Add(orphanCtrl); err != nil {
			setupLog.Error(err, "unable to register orphan controller with manager")
			os.Exit(1)
		}
		setupLog.Info("Registered orphan detection controller (leader-gated)")
	}

	// Setup webhooks only if enabled
	if enableWebhooks {
		// IMPROVEMENTS §8: validate VaultConnection at apply time instead of
		// deferring malformed-spec discovery to reconcile.
		if err := vaultwebhook.SetupVaultConnectionWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "VaultConnection")
			os.Exit(1)
		}
		if err := vaultwebhook.SetupVaultPolicyWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "VaultPolicy")
			os.Exit(1)
		}
		if err := vaultwebhook.SetupVaultClusterPolicyWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "VaultClusterPolicy")
			os.Exit(1)
		}
		if err := (&vaultwebhook.VaultRoleValidator{}).SetupWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "VaultRole")
			os.Exit(1)
		}
		if err := (&vaultwebhook.VaultClusterRoleValidator{}).SetupWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "VaultClusterRole")
			os.Exit(1)
		}
	}
	// +kubebuilder:scaffold:builder

	if metricsCertWatcher != nil {
		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {
			setupLog.Error(err, "unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
	}

	if webhookCertWatcher != nil {
		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {
			setupLog.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	// /healthz stays a trivial pulse — it only signals "the process is alive"
	// and drives pod-restart decisions. Any check more involved than Ping risks
	// flapping the liveness state on transient issues, which would spin-loop
	// the pod.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	// /readyz gates Service traffic (IMPROVEMENTS §33). Before this fix it was
	// a trivial Ping that returned 200 before informers had synced, letting
	// scrapers and webhooks race the cache. Now it fails until the shared
	// informer cache is populated.
	readyzTimeout := 2 * time.Second
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("informers-synced", func(_ *http.Request) error {
		ctx, cancel := context.WithTimeout(context.Background(), readyzTimeout)
		defer cancel()
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return errors.New("shared informer cache not synced")
		}
		return nil
	}); err != nil {
		setupLog.Error(err, "unable to register informer-sync ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// resolveOperatorNamespace returns the operator's own namespace. Tries the
// OPERATOR_NAMESPACE env var first (Helm chart wires this via downward API),
// then the in-cluster service-account namespace file, then falls back to
// the chart's default namespace. Kept local to main.go — the same logic
// exists in features/connection/controller/handler.go but is unexported there,
// and duplicating six lines beats exposing internals.
func resolveOperatorNamespace() string {
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "vault-access-operator-system"
}
