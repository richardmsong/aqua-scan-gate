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

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/richardmsong/aqua-scan-triggerer/pkg/aqua"
	"github.com/richardmsong/aqua-scan-triggerer/pkg/imageref"
)

// version information (set via ldflags during build)
var (
	version = "dev"
)

// Config holds the CLI configuration
type Config struct {
	AquaURL      string
	AquaAPIKey   string
	AquaRegistry string
	Timeout      time.Duration
	DryRun       bool
	Verbose      bool
}

func main() {
	cfg := &Config{}

	// Parse flags
	flag.StringVar(&cfg.AquaURL, "aqua-url", os.Getenv("AQUA_URL"), "Aqua server URL (or AQUA_URL env var)")
	flag.StringVar(&cfg.AquaAPIKey, "aqua-api-key", os.Getenv("AQUA_API_KEY"), "Aqua API key (or AQUA_API_KEY env var)")
	flag.StringVar(&cfg.AquaRegistry, "aqua-registry", os.Getenv("AQUA_REGISTRY"), "Aqua registry name (or AQUA_REGISTRY env var)")
	flag.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Timeout for API calls")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Print images that would be scanned without triggering scans")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output")
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

	// Run the CLI
	if err := run(ctx, cfg, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *Config, input io.Reader) error {
	// Extract images from stdin
	images, err := extractImagesFromManifests(input, cfg.Verbose)
	if err != nil {
		return fmt.Errorf("parsing manifests: %w", err)
	}

	if len(images) == 0 {
		fmt.Println("No container images found in manifests")
		return nil
	}

	// Deduplicate images
	uniqueImages := deduplicateImages(images)

	if cfg.Verbose {
		fmt.Printf("Found %d unique images to scan\n", len(uniqueImages))
	}

	// Dry run mode - just print images
	if cfg.DryRun {
		fmt.Println("Images that would be scanned:")
		for _, img := range uniqueImages {
			if img.Digest != "" {
				fmt.Printf("  - %s (digest: %s)\n", img.Image, img.Digest)
			} else {
				fmt.Printf("  - %s (no digest)\n", img.Image)
			}
		}
		return nil
	}

	// Create Aqua client
	client := aqua.NewClient(aqua.Config{
		BaseURL:  cfg.AquaURL,
		APIKey:   cfg.AquaAPIKey,
		Registry: cfg.AquaRegistry,
		Timeout:  cfg.Timeout,
	})

	// Process each image
	var scansTriggered, alreadyScanned, errors int

	for _, img := range uniqueImages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if img.Digest == "" {
			if cfg.Verbose {
				fmt.Printf("Skipping %s: no digest available\n", img.Image)
			}
			continue
		}

		// Check if already scanned
		result, err := client.GetScanResult(ctx, img.Image, img.Digest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to check scan status for %s: %v\n", img.Image, err)
			errors++
			continue
		}

		if result.Status == aqua.StatusFound {
			if cfg.Verbose {
				fmt.Printf("Already scanned: %s\n", img.Image)
			}
			alreadyScanned++
			continue
		}

		// Trigger scan
		scanID, err := client.TriggerScan(ctx, img.Image, img.Digest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to trigger scan for %s: %v\n", img.Image, err)
			errors++
			continue
		}

		fmt.Printf("Triggered scan: %s (ID: %s)\n", img.Image, scanID)
		scansTriggered++
	}

	// Print summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Scans triggered: %d\n", scansTriggered)
	fmt.Printf("  Already scanned: %d\n", alreadyScanned)
	if errors > 0 {
		fmt.Printf("  Errors: %d\n", errors)
	}

	return nil
}

// extractImagesFromManifests reads YAML manifests from the reader and extracts all container images.
func extractImagesFromManifests(r io.Reader, verbose bool) ([]imageref.ImageRef, error) {
	var allImages []imageref.ImageRef

	// Use a YAML decoder that handles multi-document YAML
	reader := yaml.NewYAMLReader(bufio.NewReader(r))

	for {
		doc, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading YAML document: %w", err)
		}

		// Skip empty documents
		if len(strings.TrimSpace(string(doc))) == 0 {
			continue
		}

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

	if podSpec == nil {
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
