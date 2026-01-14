package main

import (
	"context"
	goflag "flag"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	securityv1alpha1 "github.com/richardmsong/aqua-scan-triggerer/api/v1alpha1"
	"github.com/richardmsong/aqua-scan-triggerer/internal/controller"
	webhookpkg "github.com/richardmsong/aqua-scan-triggerer/internal/webhook"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/tracing"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
}

func main() {
	// Configure viper with AQUA prefix for automatic env var binding
	// Flags like "url" will automatically bind to AQUA_URL
	// We use explicit BindEnv only for OTEL standardized env vars
	viper.SetEnvPrefix("AQUA")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Define flags using pflag
	pflag.String("metrics-bind-address", ":8080", "Metrics endpoint address (env: AQUA_METRICS_BIND_ADDRESS)")
	pflag.String("health-probe-bind-address", ":8081", "Health probe address (env: AQUA_HEALTH_PROBE_BIND_ADDRESS)")
	pflag.Bool("leader-elect", false, "Enable leader election (env: AQUA_LEADER_ELECT)")
	pflag.String("url", "", "Aqua server URL (env: AQUA_URL)")
	pflag.String("auth-url", "", "Aqua regional auth URL (env: AQUA_AUTH_URL)")
	pflag.String("api-key", "", "Aqua API key (env: AQUA_API_KEY)")
	pflag.String("hmac-secret", "", "HMAC secret for signing (env: AQUA_HMAC_SECRET)")
	pflag.String("excluded-namespaces", "kube-system,kube-public,cert-manager", "Namespaces to exclude (env: AQUA_EXCLUDED_NAMESPACES)")
	pflag.String("scan-namespace", "", "Namespace for ImageScan CRs (env: AQUA_SCAN_NAMESPACE)")
	pflag.Duration("rescan-interval", 24*time.Hour, "Rescan interval (env: AQUA_RESCAN_INTERVAL)")
	pflag.String("registry-mirrors", "", "Registry mirror mappings (env: AQUA_REGISTRY_MIRRORS)")

	// Tracing flags - tracing is enabled when endpoint is provided
	// These use explicit BindEnv to support OTEL standardized env var names
	pflag.String("tracing-endpoint", "", "OTLP collector endpoint (env: OTEL_EXPORTER_OTLP_ENDPOINT)")
	pflag.String("tracing-protocol", "grpc", "OTLP protocol (env: OTEL_EXPORTER_OTLP_PROTOCOL)")
	pflag.Float64("tracing-sample-ratio", 1.0, "Trace sampling ratio (env: OTEL_TRACES_SAMPLER_ARG)")
	pflag.Bool("tracing-insecure", true, "Use insecure tracing (env: OTEL_EXPORTER_OTLP_INSECURE)")

	// Zap logging options - bind to standard flag package, then add to pflag
	opts := zap.Options{Development: true}
	goFlagSet := goflag.NewFlagSet("zap", goflag.ExitOnError)
	opts.BindFlags(goFlagSet)
	pflag.CommandLine.AddGoFlagSet(goFlagSet)

	pflag.Parse()

	// Bind pflags to viper
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		setupLog.Error(err, "failed to bind pflags to viper")
		os.Exit(1)
	}

	// Bind OTEL standardized environment variables explicitly
	// (these don't follow the AQUA_ prefix convention)
	_ = viper.BindEnv("tracing-endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT")
	_ = viper.BindEnv("tracing-protocol", "OTEL_EXPORTER_OTLP_PROTOCOL")
	_ = viper.BindEnv("tracing-sample-ratio", "OTEL_TRACES_SAMPLER_ARG")
	_ = viper.BindEnv("tracing-insecure", "OTEL_EXPORTER_OTLP_INSECURE")

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Get configuration values from viper (handles flag + env var precedence)
	metricsAddr := viper.GetString("metrics-bind-address")
	probeAddr := viper.GetString("health-probe-bind-address")
	enableLeaderElection := viper.GetBool("leader-elect")
	aquaURL := viper.GetString("url")
	aquaAuthURL := viper.GetString("auth-url")
	aquaAPIKey := viper.GetString("api-key")
	aquaHMACSecret := viper.GetString("hmac-secret")
	excludedNamespaces := viper.GetString("excluded-namespaces")
	scanNamespace := viper.GetString("scan-namespace")
	rescanInterval := viper.GetDuration("rescan-interval")
	registryMirrors := viper.GetString("registry-mirrors")
	tracingEndpoint := viper.GetString("tracing-endpoint")
	tracingProtocol := viper.GetString("tracing-protocol")
	tracingSampleRatio := viper.GetFloat64("tracing-sample-ratio")
	tracingInsecure := viper.GetBool("tracing-insecure")

	// Initialize tracing - enabled when endpoint is provided
	tracingCfg := tracing.Config{
		Endpoint:       tracingEndpoint,
		Protocol:       tracingProtocol,
		ServiceName:    "aqua-scan-gate-controller",
	tracingCfg := tracing.Config{
		Endpoint:       tracingEndpoint,
		Protocol:       tracingProtocol,
		ServiceName:    "aqua-scan-gate-controller",
		ServiceVersion: version, // Add var version = "dev" with ldflags override
		SampleRatio:    tracingSampleRatio,
		Insecure:       tracingInsecure,
	}
		SampleRatio:    tracingSampleRatio,
		Insecure:       tracingInsecure,
	}

	tracerProvider, err := tracing.Setup(context.Background(), tracingCfg)
	if err != nil {
		setupLog.Error(err, "failed to initialize tracing")
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
			setupLog.Error(err, "failed to shutdown tracer provider")
		}
	}()

	if tracingCfg.IsEnabled() {
		setupLog.Info("tracing enabled", "endpoint", tracingEndpoint, "protocol", tracingProtocol, "sampleRatio", tracingSampleRatio)
	}

	// Parse excluded namespaces
	excludedNS := make(map[string]bool)
	for _, ns := range strings.Split(excludedNamespaces, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			excludedNS[ns] = true
		}
	}

	// Parse registry mirrors
	mirrors, err := aqua.ParseRegistryMirrors(registryMirrors)
	if err != nil {
		setupLog.Error(err, "failed to parse registry mirrors")
		os.Exit(1)
	}
	if len(mirrors) > 0 {
		setupLog.Info("configured registry mirrors", "count", len(mirrors))
		for _, m := range mirrors {
			setupLog.Info("registry mirror", "source", m.Source, "mirror", m.Mirror)
		}
	}

	// Create Aqua client
	aquaClient := aqua.NewClient(aqua.Config{
		BaseURL: aquaURL,
		Auth: aqua.AuthConfig{
			APIKey:     aquaAPIKey,
			HMACSecret: aquaHMACSecret,
			AuthURL:    aquaAuthURL,
		},
		RegistryMirrors: mirrors,
		Timeout:         30 * time.Second,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aqua-scan-gate.security.example.com",
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Setup ImageScan controller
	if err = (&controller.ImageScanReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		AquaClient:     aquaClient,
		RescanInterval: rescanInterval,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ImageScan")
		os.Exit(1)
	}

	// Setup Pod gate controller
	if err = (&controller.PodGateReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("aqua-scan-gate"),
		ScanNamespace:      scanNamespace,
		ExcludedNamespaces: excludedNS,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodGate")
		os.Exit(1)
	}

	// Setup webhook
	mgr.GetWebhookServer().Register("/mutate-v1-pod", &webhook.Admission{
		Handler: &webhookpkg.PodMutator{
			Client:             mgr.GetClient(),
			ExcludedNamespaces: excludedNS,
		},
	})

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
