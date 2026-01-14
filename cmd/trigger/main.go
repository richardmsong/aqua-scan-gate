// Package main provides the CLI entry point for aqua-trigger.
// This tool reads Kubernetes manifests from stdin and triggers Aqua scans
// for all container images found in the manifests.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/imageref"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/tracing"
)

// version information (set via ldflags during build)
var (
	version = "dev"
)

// Config holds the CLI configuration
type Config struct {
	AquaURL         string
	AquaAuthURL     string
	AquaAPIKey      string
	AquaHMACSecret  string
	AquaRegistry    string
	RegistryMirrors string
	Timeout         time.Duration
	DryRun          bool
	Verbose         bool

	// Tracing configuration
	TracingEnabled     bool
	TracingEndpoint    string
	TracingProtocol    string
	TracingSampleRatio float64
	TracingInsecure    bool
}

func main() {
	cfg := &Config{}

	// Parse flags
	flag.StringVar(&cfg.AquaURL, "aqua-url", os.Getenv("AQUA_URL"), "Aqua server URL (or AQUA_URL env var)")
	flag.StringVar(&cfg.AquaAuthURL, "aqua-auth-url", os.Getenv("AQUA_AUTH_URL"), "Aqua regional auth URL (or AQUA_AUTH_URL env var, e.g., https://api.cloudsploit.com for US)")
	flag.StringVar(&cfg.AquaAPIKey, "aqua-api-key", os.Getenv("AQUA_API_KEY"), "Aqua API key (or AQUA_API_KEY env var)")
	flag.StringVar(&cfg.AquaHMACSecret, "aqua-hmac-secret", os.Getenv("AQUA_HMAC_SECRET"), "Aqua HMAC secret for request signing (or AQUA_HMAC_SECRET env var)")
	flag.StringVar(&cfg.AquaRegistry, "aqua-registry", os.Getenv("AQUA_REGISTRY"), "Aqua registry name (or AQUA_REGISTRY env var)")
	flag.StringVar(&cfg.RegistryMirrors, "registry-mirrors", os.Getenv("REGISTRY_MIRRORS"), "Registry mirror mappings for airgapped environments (or REGISTRY_MIRRORS env var). Format: 'source1=mirror1,source2=mirror2'. Example: 'docker.io=artifactory.internal.com/docker-remote'")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Timeout for API calls")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Print images that would be scanned without triggering scans")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output")

	// Tracing flags
	flag.BoolVar(&cfg.TracingEnabled, "tracing-enabled", getEnvBool("OTEL_TRACING_ENABLED", false), "Enable OpenTelemetry tracing (or OTEL_TRACING_ENABLED env var)")
	flag.StringVar(&cfg.TracingEndpoint, "tracing-endpoint", getEnvString("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"), "OTLP collector endpoint (or OTEL_EXPORTER_OTLP_ENDPOINT env var)")
	flag.StringVar(&cfg.TracingProtocol, "tracing-protocol", getEnvString("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"), "OTLP protocol: grpc or http (or OTEL_EXPORTER_OTLP_PROTOCOL env var)")
	flag.Float64Var(&cfg.TracingSampleRatio, "tracing-sample-ratio", getEnvFloat64("OTEL_TRACES_SAMPLER_ARG", 1.0), "Trace sampling ratio 0.0-1.0 (or OTEL_TRACES_SAMPLER_ARG env var)")
	flag.BoolVar(&cfg.TracingInsecure, "tracing-insecure", getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", true), "Disable TLS for tracing exporter (or OTEL_EXPORTER_OTLP_INSECURE env var)")

	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("aqua-trigger version %s\n", version)
		os.Exit(0)
	}

	// Validate required configuration
	if !cfg.DryRun {
		if cfg.AquaURL == "" {
			fmt.Fprintln(os.Stderr, "Error: --aqua-url or AQUA_URL is required")
			os.Exit(1)
		}
		if cfg.AquaAPIKey == "" {
			fmt.Fprintln(os.Stderr, "Error: --aqua-api-key or AQUA_API_KEY is required")
			os.Exit(1)
		}
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Set up tracing
	tracingCfg := tracing.Config{
		Enabled:        cfg.TracingEnabled,
		Endpoint:       cfg.TracingEndpoint,
		Protocol:       cfg.TracingProtocol,
		ServiceName:    "aqua-trigger",
		ServiceVersion: version,
		SampleRatio:    cfg.TracingSampleRatio,
		Insecure:       cfg.TracingInsecure,
	}
	tp, err := tracing.Setup(ctx, tracingCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to setup tracing: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to shutdown tracer: %v\n", err)
		}
	}()

	// Run the CLI
	if err := run(ctx, cfg, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *Config, input io.Reader) error {
	// Start the main span
	ctx, span := tracing.StartSpan(ctx, "aqua-trigger.run",
		trace.WithAttributes(
			attribute.Bool("dry_run", cfg.DryRun),
			attribute.Bool("verbose", cfg.Verbose),
		),
	)
	defer span.End()

	// Extract images from stdin
	images, err := extractImagesFromManifests(ctx, input, cfg.Verbose)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to parse manifests")
		return fmt.Errorf("parsing manifests: %w", err)
	}

	if len(images) == 0 {
		fmt.Println("No container images found in manifests")
		span.SetAttributes(attribute.Int("images.count", 0))
		return nil
	}

	// Deduplicate images
	uniqueImages := deduplicateImages(images)
	span.SetAttributes(attribute.Int("images.unique_count", len(uniqueImages)))

	if cfg.Verbose {
		fmt.Printf("Found %d unique images to process\n", len(uniqueImages))
	}

	// Create image resolver for resolving tags to digests (linux/amd64)
	resolver := imageref.NewResolver()

	// Resolve digests for images that don't have them
	var resolvedImages []imageref.ImageRef
	var resolveErrors int
	for _, img := range uniqueImages {
		if img.Digest != "" {
			// Already has a digest
			resolvedImages = append(resolvedImages, img)
			continue
		}

		// Start span for digest resolution
		resolveCtx, resolveSpan := tracing.StartSpan(ctx, "aqua-trigger.resolve_digest",
			trace.WithAttributes(
				tracing.AttrImageName.String(img.Image),
			),
		)

		if cfg.Verbose {
			fmt.Printf("Resolving digest for %s (linux/amd64)...\n", img.Image)
		}

		resolved, err := resolver.ResolveImageRef(resolveCtx, img)
		if err != nil {
			resolveSpan.RecordError(err)
			resolveSpan.SetStatus(codes.Error, "failed to resolve digest")
			resolveSpan.End()
			fmt.Fprintf(os.Stderr, "Error: failed to resolve digest for %s: %v\n", img.Image, err)
			resolveErrors++
			continue
		}

		resolveSpan.SetAttributes(tracing.AttrImageDigest.String(resolved.Digest))
		resolveSpan.End()

		if cfg.Verbose {
			fmt.Printf("  -> %s\n", resolved.Digest)
		}
		resolvedImages = append(resolvedImages, resolved)
	}

	span.SetAttributes(
		attribute.Int("images.resolved_count", len(resolvedImages)),
		attribute.Int("images.resolve_errors", resolveErrors),
	)

	if resolveErrors > 0 && len(resolvedImages) == 0 {
		span.SetStatus(codes.Error, "failed to resolve any images")
		return fmt.Errorf("failed to resolve any images")
	}

	// Parse registry mirrors
	var registryMirrors []aqua.RegistryMirror
	if cfg.RegistryMirrors != "" {
		var err error
		registryMirrors, err = aqua.ParseRegistryMirrors(cfg.RegistryMirrors)
		if err != nil {
			return fmt.Errorf("parsing registry mirrors: %w", err)
		}
		if cfg.Verbose && len(registryMirrors) > 0 {
			fmt.Printf("Configured registry mirrors:\n")
			for _, m := range registryMirrors {
				fmt.Printf("  %s -> %s\n", m.Source, m.Mirror)
			}
		}
	}

	// Dry run mode - just print images
	if cfg.DryRun {
		fmt.Println("Images that would be scanned:")
		for _, img := range resolvedImages {
			fmt.Printf("  - %s (digest: %s)\n", img.Image, img.Digest)
		}
		if resolveErrors > 0 {
			fmt.Printf("\nFailed to resolve: %d images\n", resolveErrors)
		}
		return nil
	}

	// Create Aqua client
	client := aqua.NewClient(aqua.Config{
		BaseURL:         cfg.AquaURL,
		APIKey:          cfg.AquaAPIKey,
		Registry:        cfg.AquaRegistry,
		RegistryMirrors: registryMirrors,
		Timeout:         cfg.Timeout,
		Verbose:         cfg.Verbose,
		Auth: aqua.AuthConfig{
			APIKey:     cfg.AquaAPIKey,
			HMACSecret: cfg.AquaHMACSecret,
			AuthURL:    cfg.AquaAuthURL,
		},
	})

	// Process each image
	var scansTriggered, alreadyScanned, scanErrors int

	for _, img := range resolvedImages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Start span for processing this image
		imgCtx, imgSpan := tracing.StartSpan(ctx, "aqua-trigger.process_image",
			trace.WithAttributes(
				tracing.AttrImageName.String(img.Image),
				tracing.AttrImageDigest.String(img.Digest),
			),
		)

		// Check if already scanned
		if cfg.Verbose {
			fmt.Printf("Checking scan status for %s (%s)...\n", img.Image, img.Digest)
		}
		result, err := client.GetScanResult(imgCtx, img.Image, img.Digest)
		if err != nil {
			imgSpan.RecordError(err)
			imgSpan.SetStatus(codes.Error, "failed to check scan status")
			imgSpan.End()
			fmt.Fprintf(os.Stderr, "Error: failed to check scan status for %s: %v\n", img.Image, err)
			scanErrors++
			continue
		}

		imgSpan.SetAttributes(tracing.AttrScanStatus.String(string(result.Status)))

		if cfg.Verbose {
			fmt.Printf("  Scan status: %s\n", result.Status)
		}

		if result.Status == aqua.StatusFound {
			if cfg.Verbose {
				fmt.Printf("  -> Already scanned, skipping\n")
			}
			imgSpan.SetAttributes(attribute.Bool("scan.already_scanned", true))
			imgSpan.End()
			alreadyScanned++
			continue
		}

		// Trigger scan
		if cfg.Verbose {
			fmt.Printf("  -> Not found, triggering scan...\n")
		}
		scanID, err := client.TriggerScan(imgCtx, img.Image, img.Digest)
		if err != nil {
			imgSpan.RecordError(err)
			imgSpan.SetStatus(codes.Error, "failed to trigger scan")
			imgSpan.End()
			fmt.Fprintf(os.Stderr, "Error: failed to trigger scan for %s: %v\n", img.Image, err)
			scanErrors++
			continue
		}

		imgSpan.SetAttributes(
			tracing.AttrScanID.String(scanID),
			attribute.Bool("scan.triggered", true),
		)
		imgSpan.End()

		fmt.Printf("Triggered scan: %s (ID: %s)\n", img.Image, scanID)
		scansTriggered++
	}

	// Set final summary attributes on main span
	span.SetAttributes(
		attribute.Int("summary.scans_triggered", scansTriggered),
		attribute.Int("summary.already_scanned", alreadyScanned),
		attribute.Int("summary.resolve_errors", resolveErrors),
		attribute.Int("summary.scan_errors", scanErrors),
	)

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Scans triggered: %d\n", scansTriggered)
	fmt.Printf("  Already scanned: %d\n", alreadyScanned)
	if resolveErrors > 0 {
		fmt.Printf("  Failed to resolve: %d\n", resolveErrors)
	}
	if scanErrors > 0 {
		fmt.Printf("  Scan errors: %d\n", scanErrors)
	}

	totalErrors := resolveErrors + scanErrors
	if totalErrors > 0 {
		span.SetStatus(codes.Error, fmt.Sprintf("%d images failed", totalErrors))
		return fmt.Errorf("%d images failed", totalErrors)
	}

	return nil
}

// extractImagesFromManifests reads YAML manifests from the reader and extracts all container images.
func extractImagesFromManifests(ctx context.Context, r io.Reader, verbose bool) ([]imageref.ImageRef, error) {
	_, span := tracing.StartSpan(ctx, "aqua-trigger.extract_images")
	defer span.End()

	var allImages []imageref.ImageRef

	// Use a YAML decoder that handles multi-document YAML
	reader := yaml.NewYAMLReader(bufio.NewReader(r))

	documentsProcessed := 0
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to read YAML document")
			return nil, fmt.Errorf("reading YAML document: %w", err)
		}

		// Skip empty documents
		if len(strings.TrimSpace(string(doc))) == 0 {
			continue
		}

		documentsProcessed++
		images, err := extractImagesFromDocument(doc, verbose)
		if err != nil {
			// Log warning but continue processing other documents
			if verbose {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse document: %v\n", err)
			}
			continue
		}

		allImages = append(allImages, images...)
	}

	span.SetAttributes(
		attribute.Int("documents.processed", documentsProcessed),
		attribute.Int("images.extracted", len(allImages)),
	)

	return allImages, nil
}

// extractImagesFromDocument extracts images from a single YAML document.
// It handles Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, and ReplicaSets.
func extractImagesFromDocument(doc []byte, verbose bool) ([]imageref.ImageRef, error) {
	// First, try to determine the kind of resource
	var typeMeta struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(doc, &typeMeta); err != nil {
		return nil, fmt.Errorf("parsing type meta: %w", err)
	}

	if verbose {
		fmt.Printf("Processing %s\n", typeMeta.Kind)
	}

	var podSpec *corev1.PodSpec

	switch typeMeta.Kind {
	case "Pod":
		var pod corev1.Pod
		if err := yaml.Unmarshal(doc, &pod); err != nil {
			return nil, fmt.Errorf("parsing Pod: %w", err)
		}
		podSpec = &pod.Spec

	case "Deployment":
		var deployment appsv1.Deployment
		if err := yaml.Unmarshal(doc, &deployment); err != nil {
			return nil, fmt.Errorf("parsing Deployment: %w", err)
		}
		podSpec = &deployment.Spec.Template.Spec

	case "StatefulSet":
		var statefulSet appsv1.StatefulSet
		if err := yaml.Unmarshal(doc, &statefulSet); err != nil {
			return nil, fmt.Errorf("parsing StatefulSet: %w", err)
		}
		podSpec = &statefulSet.Spec.Template.Spec

	case "DaemonSet":
		var daemonSet appsv1.DaemonSet
		if err := yaml.Unmarshal(doc, &daemonSet); err != nil {
			return nil, fmt.Errorf("parsing DaemonSet: %w", err)
		}
		podSpec = &daemonSet.Spec.Template.Spec

	case "ReplicaSet":
		var replicaSet appsv1.ReplicaSet
		if err := yaml.Unmarshal(doc, &replicaSet); err != nil {
			return nil, fmt.Errorf("parsing ReplicaSet: %w", err)
		}
		podSpec = &replicaSet.Spec.Template.Spec

	case "Job":
		var job batchv1.Job
		if err := yaml.Unmarshal(doc, &job); err != nil {
			return nil, fmt.Errorf("parsing Job: %w", err)
		}
		podSpec = &job.Spec.Template.Spec

	case "CronJob":
		var cronJob batchv1.CronJob
		if err := yaml.Unmarshal(doc, &cronJob); err != nil {
			return nil, fmt.Errorf("parsing CronJob: %w", err)
		}
		podSpec = &cronJob.Spec.JobTemplate.Spec.Template.Spec

	default:
		// Unknown or unsupported kind, skip silently
		return nil, nil
	}

	return imageref.ExtractFromPodSpec(podSpec), nil
}

// deduplicateImages returns a deduplicated list of images.
func deduplicateImages(images []imageref.ImageRef) []imageref.ImageRef {
	seen := make(map[string]bool)
	var result []imageref.ImageRef

	for _, img := range images {
		if !seen[img.Image] {
			seen[img.Image] = true
			result = append(result, img)
		}
	}

	return result
}

// getEnvBool returns the boolean value of an environment variable, or the default value if not set.
func getEnvBool(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val == "true" || val == "1" || val == "yes"
}

// getEnvString returns the string value of an environment variable, or the default value if not set.
func getEnvString(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val
}

// getEnvFloat64 returns the float64 value of an environment variable, or the default value if not set.
func getEnvFloat64(key string, defaultValue float64) float64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	var f float64
	if _, err := fmt.Sscanf(val, "%f", &f); err != nil {
		return defaultValue
	}
	return f
}
