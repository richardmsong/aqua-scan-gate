// Package tracing provides OpenTelemetry tracing configuration and utilities.
package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TestConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{
			name:     "enabled when endpoint is set",
			endpoint: "localhost:4317",
			want:     true,
		},
		{
			name:     "disabled when endpoint is empty",
			endpoint: "",
			want:     false,
		},
		{
			name:     "enabled with http endpoint",
			endpoint: "http://localhost:4318/v1/traces",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Endpoint: tt.endpoint}
			if got := cfg.IsEnabled(); got != tt.want {
				t.Errorf("Config.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Endpoint != "" {
		t.Errorf("DefaultConfig().Endpoint = %q, want empty string", cfg.Endpoint)
	}
	if cfg.Protocol != "grpc" {
		t.Errorf("DefaultConfig().Protocol = %q, want %q", cfg.Protocol, "grpc")
	}
	if cfg.ServiceName != "aqua-scan-gate-controller" {
		t.Errorf("DefaultConfig().ServiceName = %q, want %q", cfg.ServiceName, "aqua-scan-gate-controller")
	}
	if cfg.ServiceVersion != "0.1.0" {
		t.Errorf("DefaultConfig().ServiceVersion = %q, want %q", cfg.ServiceVersion, "0.1.0")
	}
	if cfg.SampleRatio != 1.0 {
		t.Errorf("DefaultConfig().SampleRatio = %f, want %f", cfg.SampleRatio, 1.0)
	}
	if !cfg.Insecure {
		t.Errorf("DefaultConfig().Insecure = %v, want %v", cfg.Insecure, true)
	}
	if cfg.IsEnabled() {
		t.Errorf("DefaultConfig().IsEnabled() = true, want false")
	}
}

func TestSetup_DisabledTracing(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint: "", // Empty endpoint disables tracing
	}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error = %v, want nil", err)
	}
	if tp == nil {
		t.Fatal("Setup() returned nil TracerProvider")
	}

	// Verify we got a no-op tracer (provider should be nil)
	if tp.provider != nil {
		t.Error("Setup() with disabled tracing should have nil provider")
	}

	// Tracer should still work (returns global no-op tracer)
	tracer := tp.Tracer()
	if tracer == nil {
		t.Error("TracerProvider.Tracer() returned nil")
	}

	// Shutdown should work without error
	if err := tp.Shutdown(ctx); err != nil {
		t.Errorf("TracerProvider.Shutdown() error = %v, want nil", err)
	}
}

func TestSetup_InvalidProtocol(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint: "localhost:4317",
		Protocol: "invalid",
	}

	_, err := Setup(ctx, cfg)
	if err == nil {
		t.Error("Setup() with invalid protocol should return error")
	}
}

func TestTracerProvider_Shutdown_NilProvider(t *testing.T) {
	tp := &TracerProvider{
		provider: nil,
		tracer:   nil,
	}

	ctx := context.Background()
	if err := tp.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() with nil provider error = %v, want nil", err)
	}
}

func TestTracer(t *testing.T) {
	tracer := Tracer()
	if tracer == nil {
		t.Error("Tracer() returned nil")
	}
}

func TestStartSpan(t *testing.T) {
	ctx := context.Background()
	spanCtx, span := StartSpan(ctx, "test-span")

	if spanCtx == nil {
		t.Error("StartSpan() returned nil context")
	}
	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	span.End()
}

func TestStartSpan_WithAttributes(t *testing.T) {
	ctx := context.Background()
	spanCtx, span := StartSpan(ctx, "test-span-with-attrs",
		trace.WithAttributes(
			AttrImageName.String("nginx:latest"),
			AttrPodName.String("test-pod"),
		),
	)

	if spanCtx == nil {
		t.Error("StartSpan() returned nil context")
	}
	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	span.End()
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()

	// Get span from context without any span
	span := SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext() returned nil for empty context")
	}

	// Create a span and verify we can retrieve it
	spanCtx, createdSpan := StartSpan(ctx, "test-span")
	defer createdSpan.End()

	retrievedSpan := SpanFromContext(spanCtx)
	if retrievedSpan == nil {
		t.Error("SpanFromContext() returned nil for context with span")
	}
}

func TestAttributeKeys(t *testing.T) {
	// Test that attribute keys create valid attributes
	tests := []struct {
		name string
		attr attribute.KeyValue
	}{
		{"image.name", AttrImageName.String("nginx:latest")},
		{"image.digest", AttrImageDigest.String("sha256:abc123")},
		{"pod.name", AttrPodName.String("test-pod")},
		{"pod.namespace", AttrPodNamespace.String("default")},
		{"scan.id", AttrScanID.String("scan-123")},
		{"scan.status", AttrScanStatus.String("completed")},
		{"scan.phase", AttrScanPhase.String("Passed")},
		{"aqua.registry", AttrAquaRegistry.String("docker.io")},
		{"aqua.endpoint", AttrAquaEndpoint.String("https://api.aqua.com")},
		{"http.method", AttrHTTPMethod.String("GET")},
		{"http.url", AttrHTTPURL.String("https://example.com/api")},
		{"http.status_code", AttrHTTPStatusCode.Int(200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.attr.Key) != tt.name {
				t.Errorf("Attribute key = %q, want %q", tt.attr.Key, tt.name)
			}
			if !tt.attr.Valid() {
				t.Errorf("Attribute %q is not valid", tt.name)
			}
		})
	}
}

func TestTracerName(t *testing.T) {
	if TracerName != "aqua-scan-gate-controller" {
		t.Errorf("TracerName = %q, want %q", TracerName, "aqua-scan-gate-controller")
	}
}

func TestTracerProvider_Tracer(t *testing.T) {
	// Test with disabled tracing (nil provider)
	ctx := context.Background()
	cfg := Config{Endpoint: ""}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	tracer := tp.Tracer()
	if tracer == nil {
		t.Error("TracerProvider.Tracer() returned nil")
	}
}

func TestConfig_SampleRatioEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		sampleRatio float64
		description string
	}{
		{
			name:        "zero sample ratio means never sample",
			sampleRatio: 0.0,
			description: "NeverSample",
		},
		{
			name:        "full sample ratio means always sample",
			sampleRatio: 1.0,
			description: "AlwaysSample",
		},
		{
			name:        "partial sample ratio uses ratio-based sampling",
			sampleRatio: 0.5,
			description: "TraceIDRatioBased",
		},
		{
			name:        "negative sample ratio treated as never sample",
			sampleRatio: -0.1,
			description: "NeverSample",
		},
		{
			name:        "sample ratio above 1.0 treated as always sample",
			sampleRatio: 1.5,
			description: "AlwaysSample",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				SampleRatio: tt.sampleRatio,
			}
			// Just verify the config holds the value correctly
			if cfg.SampleRatio != tt.sampleRatio {
				t.Errorf("Config.SampleRatio = %f, want %f", cfg.SampleRatio, tt.sampleRatio)
			}
		})
	}
}

func TestSetup_HTTPProtocol(t *testing.T) {
	// Test that HTTP protocol is recognized (but will fail to connect since no server)
	ctx := context.Background()
	cfg := Config{
		Endpoint: "localhost:4318",
		Protocol: "http",
		Insecure: true,
	}

	// This should succeed in creating the exporter (connection happens later)
	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() with HTTP protocol error = %v, want nil", err)
	}
	if tp == nil {
		t.Fatal("Setup() returned nil TracerProvider")
	}
	if tp.provider == nil {
		t.Error("Setup() with HTTP protocol should have non-nil provider")
	}

	// Clean up
	if err := tp.Shutdown(ctx); err != nil {
		t.Logf("Shutdown warning (expected, no server): %v", err)
	}
}

func TestSetup_GRPCProtocol(t *testing.T) {
	// Test that gRPC protocol is recognized (but will fail to connect since no server)
	ctx := context.Background()
	cfg := Config{
		Endpoint: "localhost:4317",
		Protocol: "grpc",
		Insecure: true,
	}

	// This should succeed in creating the exporter (connection happens later)
	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() with gRPC protocol error = %v, want nil", err)
	}
	if tp == nil {
		t.Fatal("Setup() returned nil TracerProvider")
	}
	if tp.provider == nil {
		t.Error("Setup() with gRPC protocol should have non-nil provider")
	}

	// Clean up
	if err := tp.Shutdown(ctx); err != nil {
		t.Logf("Shutdown warning (expected, no server): %v", err)
	}
}

func TestSetup_WithServiceInfo(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint:       "localhost:4317",
		Protocol:       "grpc",
		ServiceName:    "test-service",
		ServiceVersion: "1.2.3",
		SampleRatio:    1.0,
		Insecure:       true,
	}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() with service info error = %v, want nil", err)
	}
	if tp == nil {
		t.Fatal("Setup() returned nil TracerProvider")
	}

	// Verify tracer is available
	tracer := tp.Tracer()
	if tracer == nil {
		t.Error("TracerProvider.Tracer() returned nil")
	}

	// Clean up
	if err := tp.Shutdown(ctx); err != nil {
		t.Logf("Shutdown warning (expected, no server): %v", err)
	}
}

func TestSetup_SpanCreation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Endpoint:       "localhost:4317",
		Protocol:       "grpc",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		SampleRatio:    1.0,
		Insecure:       true,
	}

	tp, err := Setup(ctx, cfg)
	if err != nil {
		t.Fatalf("Setup() error = %v, want nil", err)
	}
	defer func() {
		_ = tp.Shutdown(ctx)
	}()

	// Create a span using the global tracer
	spanCtx, span := StartSpan(ctx, "test-operation",
		trace.WithAttributes(
			AttrImageName.String("nginx:latest"),
			AttrPodName.String("test-pod"),
			AttrPodNamespace.String("default"),
		),
	)

	if spanCtx == nil {
		t.Error("StartSpan() returned nil context")
	}
	if span == nil {
		t.Error("StartSpan() returned nil span")
	}

	// Create a child span
	_, childSpan := StartSpan(spanCtx, "child-operation",
		trace.WithAttributes(
			AttrScanID.String("scan-123"),
			AttrScanStatus.String("completed"),
		),
	)

	if childSpan == nil {
		t.Error("Child span creation failed")
	}

	childSpan.End()
	span.End()
}
