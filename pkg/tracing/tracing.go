// Package tracing provides OpenTelemetry tracing configuration and utilities.
package tracing

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the name used for the tracer
	TracerName = "aqua-scan-gate-controller"
)

// Config holds the tracing configuration
type Config struct {
	// Endpoint is the OTLP collector endpoint (host:port format)
	// For gRPC: "localhost:4317"
	// For HTTP: "localhost:4318" (path /v1/traces is added automatically)
	// If empty, tracing is disabled
	Endpoint string

	// Protocol specifies the OTLP protocol to use ("grpc" or "http")
	Protocol string

	// ServiceName is the name of the service for traces
	ServiceName string

	// ServiceVersion is the version of the service
	ServiceVersion string

	// SampleRatio determines what fraction of traces to sample (0.0 to 1.0)
	// 1.0 means sample all traces
	SampleRatio float64

	// Insecure disables TLS for the exporter (for development)
	Insecure bool
}

// DefaultConfig returns a default tracing configuration
func DefaultConfig() Config {
	return Config{
		Endpoint:       "", // Empty means tracing disabled
		Protocol:       "grpc",
		ServiceName:    "aqua-scan-gate-controller",
		ServiceVersion: "0.1.0",
		SampleRatio:    1.0,
		Insecure:       true,
	}
}

// IsEnabled returns true if tracing is enabled (i.e., endpoint is configured)
func (c Config) IsEnabled() bool {
	return c.Endpoint != ""
}

// TracerProvider wraps the OpenTelemetry tracer provider and provides convenience methods
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// Setup initializes the OpenTelemetry tracing with the given configuration.
// It returns a TracerProvider that should be shut down when the application exits.
// If the endpoint is empty, tracing is disabled and a no-op tracer is returned.
func Setup(ctx context.Context, cfg Config) (*TracerProvider, error) {
	if !cfg.IsEnabled() {
		// Return a no-op tracer provider
		return &TracerProvider{
			tracer: otel.Tracer(TracerName),
		}, nil
	}

	// Create the resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("service.component", "controller"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource: %w", err)
	}

	// Create the OTLP exporter based on protocol
	var exporter *otlptrace.Exporter
	switch cfg.Protocol {
	case "grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, opts...)
	case "http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(cfg.Endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s (use 'grpc' or 'http')", cfg.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("creating OTLP exporter: %w", err)
	}

	// Create sampler with warning for out-of-range values
	var sampler sdktrace.Sampler
	if cfg.SampleRatio < 0.0 || cfg.SampleRatio > 1.0 {
		slog.Warn("tracing sample ratio outside valid range [0.0, 1.0], clamping value",
			"configured", cfg.SampleRatio,
			"clamped", clampSampleRatio(cfg.SampleRatio))
	}
	if cfg.SampleRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRatio <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}

	// Create the tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set the global tracer provider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &TracerProvider{
		provider: tp,
		tracer:   tp.Tracer(TracerName),
	}, nil
}

// Shutdown gracefully shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider != nil {
		return tp.provider.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the tracer instance
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// Tracer returns the global tracer for the application
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// StartSpan starts a new span with the given name and returns the context and span.
// This is a convenience function that uses the global tracer.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// clampSampleRatio returns the clamped sample ratio value for logging purposes
func clampSampleRatio(ratio float64) float64 {
	if ratio < 0.0 {
		return 0.0
	}
	if ratio > 1.0 {
		return 1.0
	}
	return ratio
}

// Common attribute keys for tracing
var (
	// ImageAttributes
	AttrImageName   = attribute.Key("image.name")
	AttrImageDigest = attribute.Key("image.digest")

	// Pod attributes
	AttrPodName      = attribute.Key("pod.name")
	AttrPodNamespace = attribute.Key("pod.namespace")

	// Scan attributes
	AttrScanID     = attribute.Key("scan.id")
	AttrScanStatus = attribute.Key("scan.status")
	AttrScanPhase  = attribute.Key("scan.phase")

	// Aqua API attributes
	AttrAquaRegistry = attribute.Key("aqua.registry")
	AttrAquaEndpoint = attribute.Key("aqua.endpoint")

	// HTTP attributes - using OpenTelemetry semantic conventions for interoperability
	AttrHTTPMethod     = semconv.HTTPRequestMethodKey
	AttrHTTPURL        = semconv.URLFullKey
	AttrHTTPStatusCode = semconv.HTTPResponseStatusCodeKey
)
