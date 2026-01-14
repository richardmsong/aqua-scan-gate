package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
	var (
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		aquaURL              string
		aquaAuthURL          string
		aquaAPIKey           string
		aquaHMACSecret       string
		excludedNamespaces   string
		scanNamespace        string
		rescanInterval       time.Duration
		registryMirrors      string
		// Tracing configuration
		tracingEnabled     bool
		tracingEndpoint    string
		tracingProtocol    string
		tracingSampleRatio float64
		tracingInsecure    bool
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election.")
	flag.StringVar(&aquaURL, "aqua-url", os.Getenv("AQUA_URL"), "Aqua server URL")
	flag.StringVar(&aquaAuthURL, "aqua-auth-url", os.Getenv("AQUA_AUTH_URL"), "Aqua regional auth URL (e.g., https://api.cloudsploit.com for US)")
	flag.StringVar(&aquaAPIKey, "aqua-api-key", os.Getenv("AQUA_API_KEY"), "Aqua API key for authentication")
	flag.StringVar(&aquaHMACSecret, "aqua-hmac-secret", os.Getenv("AQUA_HMAC_SECRET"), "HMAC secret for request signing (optional)")
	flag.StringVar(&excludedNamespaces, "excluded-namespaces", "kube-system,kube-public,cert-manager", "Comma-separated namespaces to exclude")
	flag.StringVar(&scanNamespace, "scan-namespace", "", "Namespace for ImageScan CRs (empty = same as pod)")
	flag.DurationVar(&rescanInterval, "rescan-interval", 24*time.Hour, "Interval for rescanning images")
	flag.StringVar(&registryMirrors, "registry-mirrors", os.Getenv("REGISTRY_MIRRORS"), "Comma-separated registry mirror mappings (e.g., 'docker.io=artifactory.internal.com/docker-remote,gcr.io=artifactory.internal.com/gcr-remote')")

	// Tracing flags
	flag.BoolVar(&tracingEnabled, "tracing-enabled", getEnvBool("OTEL_TRACING_ENABLED", false), "Enable OpenTelemetry tracing")
	flag.StringVar(&tracingEndpoint, "tracing-endpoint", getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"), "OTLP collector endpoint")
	flag.StringVar(&tracingProtocol, "tracing-protocol", getEnv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"), "OTLP protocol (grpc or http)")
	flag.Float64Var(&tracingSampleRatio, "tracing-sample-ratio", getEnvFloat("OTEL_TRACES_SAMPLER_ARG", 1.0), "Trace sampling ratio (0.0-1.0)")
	flag.BoolVar(&tracingInsecure, "tracing-insecure", getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", true), "Use insecure connection for tracing")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Initialize tracing
	tracingCfg := tracing.Config{
		Enabled:        tracingEnabled,
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
		if err := tracerProvider.Shutdown(context.Background()); err != nil {
			setupLog.Error(err, "failed to shutdown tracer provider")
		}
	}()

	if tracingEnabled {
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

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool returns the boolean value of an environment variable or a default value
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return defaultValue
}

// getEnvFloat returns the float64 value of an environment variable or a default value
func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		var f float64
		_, err := parseFloat(value, &f)
		if err == nil {
			return f
		}
	}
	return defaultValue
}

// parseFloat is a simple float parser
func parseFloat(s string, f *float64) (int, error) {
	var err error
	*f, err = strconvParseFloat(s)
	if err != nil {
		return 0, err
	}
	return len(s), nil
}

// strconvParseFloat parses a string to float64
func strconvParseFloat(s string) (float64, error) {
	// Simple implementation using fmt.Sscanf
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}
