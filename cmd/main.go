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
	// Configure viper
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Define flags using pflag
	pflag.String("metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	pflag.String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	pflag.Bool("leader-elect", false, "Enable leader election.")
	pflag.String("aqua-url", "", "Aqua server URL")
	pflag.String("aqua-auth-url", "", "Aqua regional auth URL (e.g., https://api.cloudsploit.com for US)")
	pflag.String("aqua-api-key", "", "Aqua API key for authentication")
	pflag.String("aqua-hmac-secret", "", "HMAC secret for request signing (optional)")
	pflag.String("excluded-namespaces", "kube-system,kube-public,cert-manager", "Comma-separated namespaces to exclude")
	pflag.String("scan-namespace", "", "Namespace for ImageScan CRs (empty = same as pod)")
	pflag.Duration("rescan-interval", 24*time.Hour, "Interval for rescanning images")
	pflag.String("registry-mirrors", "", "Comma-separated registry mirror mappings (e.g., 'docker.io=artifactory.internal.com/docker-remote,gcr.io=artifactory.internal.com/gcr-remote')")

	// Tracing flags - tracing is enabled when endpoint is provided
	pflag.String("tracing-endpoint", "", "OTLP collector endpoint (enables tracing when set)")
	pflag.String("tracing-protocol", "grpc", "OTLP protocol (grpc or http)")
	pflag.Float64("tracing-sample-ratio", 1.0, "Trace sampling ratio (0.0-1.0)")
	pflag.Bool("tracing-insecure", true, "Use insecure connection for tracing")

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

	// Bind environment variables for configuration
	_ = viper.BindEnv("aqua-url", "AQUA_URL")
	_ = viper.BindEnv("aqua-auth-url", "AQUA_AUTH_URL")
	_ = viper.BindEnv("aqua-api-key", "AQUA_API_KEY")
	_ = viper.BindEnv("aqua-hmac-secret", "AQUA_HMAC_SECRET")
	_ = viper.BindEnv("registry-mirrors", "REGISTRY_MIRRORS")
	_ = viper.BindEnv("tracing-endpoint", "OTEL_EXPORTER_OTLP_ENDPOINT")
	_ = viper.BindEnv("tracing-protocol", "OTEL_EXPORTER_OTLP_PROTOCOL")
	_ = viper.BindEnv("tracing-sample-ratio", "OTEL_TRACES_SAMPLER_ARG")
	_ = viper.BindEnv("tracing-insecure", "OTEL_EXPORTER_OTLP_INSECURE")

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Get configuration values from viper (handles flag + env var precedence)
	metricsAddr := viper.GetString("metrics-bind-address")
	probeAddr := viper.GetString("health-probe-bind-address")
	enableLeaderElection := viper.GetBool("leader-elect")
	aquaURL := viper.GetString("aqua-url")
	aquaAuthURL := viper.GetString("aqua-auth-url")
	aquaAPIKey := viper.GetString("aqua-api-key")
	aquaHMACSecret := viper.GetString("aqua-hmac-secret")
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
		ServiceVersion: "0.1.0",
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
