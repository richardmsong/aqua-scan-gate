package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/richardmsong/aqua-scan-triggerer/pkg/imageref"
)

func TestExtractImagesFromManifests(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name: "single pod",
			input: `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx:latest
`,
			expected: []string{"nginx:latest"},
		},
		{
			name: "deployment",
			input: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.19
`,
			expected: []string{"nginx:1.19"},
		},
		{
			name: "statefulset",
			input: `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: test-statefulset
spec:
  template:
    spec:
      containers:
      - name: app
        image: redis:6
`,
			expected: []string{"redis:6"},
		},
		{
			name: "daemonset",
			input: `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset
spec:
  template:
    spec:
      containers:
      - name: agent
        image: fluentd:latest
`,
			expected: []string{"fluentd:latest"},
		},
		{
			name: "job",
			input: `
apiVersion: batch/v1
kind: Job
metadata:
  name: test-job
spec:
  template:
    spec:
      containers:
      - name: worker
        image: busybox:1.35
`,
			expected: []string{"busybox:1.35"},
		},
		{
			name: "cronjob",
			input: `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: test-cronjob
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: worker
            image: alpine:3.14
`,
			expected: []string{"alpine:3.14"},
		},
		{
			name: "replicaset",
			input: `
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: test-replicaset
spec:
  template:
    spec:
      containers:
      - name: app
        image: httpd:2.4
`,
			expected: []string{"httpd:2.4"},
		},
		{
			name: "multi-document yaml",
			input: `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  containers:
  - name: app
    image: nginx:latest
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  containers:
  - name: app
    image: redis:6
`,
			expected: []string{"nginx:latest", "redis:6"},
		},
		{
			name: "pod with init containers",
			input: `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  initContainers:
  - name: init
    image: busybox:latest
  containers:
  - name: app
    image: nginx:latest
`,
			expected: []string{"busybox:latest", "nginx:latest"},
		},
		{
			name: "unknown resource type",
			input: `
apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  ports:
  - port: 80
`,
			expected: nil,
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name: "deployment with multiple containers",
			input: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
      - name: sidecar
        image: envoyproxy/envoy:v1.20
`,
			expected: []string{"nginx:latest", "envoyproxy/envoy:v1.20"},
		},
		{
			name: "image with digest",
			input: `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc123def456789012345678901234567890123456789012345678901234
`,
			expected: []string{"nginx@sha256:abc123def456789012345678901234567890123456789012345678901234"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			images, err := extractImagesFromManifests(reader, false)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Extract image names for comparison
			var imageNames []string
			for _, img := range images {
				imageNames = append(imageNames, img.Image)
			}

			if len(imageNames) != len(tt.expected) {
				t.Errorf("expected %d images, got %d: %v", len(tt.expected), len(imageNames), imageNames)
				return
			}

			for i, exp := range tt.expected {
				if imageNames[i] != exp {
					t.Errorf("expected image %q at position %d, got %q", exp, i, imageNames[i])
				}
			}
		})
	}
}

func TestDeduplicateImages(t *testing.T) {
	tests := []struct {
		name     string
		input    []imageref.ImageRef
		expected int
	}{
		{
			name:     "no duplicates",
			input:    []imageref.ImageRef{{Image: "nginx:latest"}, {Image: "redis:6"}},
			expected: 2,
		},
		{
			name:     "with duplicates",
			input:    []imageref.ImageRef{{Image: "nginx:latest"}, {Image: "nginx:latest"}, {Image: "redis:6"}},
			expected: 2,
		},
		{
			name:     "all duplicates",
			input:    []imageref.ImageRef{{Image: "nginx:latest"}, {Image: "nginx:latest"}},
			expected: 1,
		},
		{
			name:     "empty input",
			input:    nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateImages(tt.input)

			if len(result) != tt.expected {
				t.Errorf("expected %d unique images, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestExtractImagesFromDocument(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		expected int
		wantErr  bool
	}{
		{
			name: "valid pod",
			doc: `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: app
    image: nginx:latest`,
			expected: 1,
		},
		{
			name: "invalid yaml",
			doc: `apiVersion: v1
kind: Pod
metadata
  name: test`,
			wantErr: true,
		},
		{
			name: "unsupported kind",
			doc: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			images, err := extractImagesFromDocument([]byte(tt.doc), false)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(images) != tt.expected {
				t.Errorf("expected %d images, got %d", tt.expected, len(images))
			}
		})
	}
}

func TestRunDryRun(t *testing.T) {
	cfg := &Config{
		DryRun:  true,
		Verbose: false,
	}

	input := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc123def456789012345678901234567890123456789012345678901234
`

	var output bytes.Buffer
	// Note: run() writes to stdout, so we can't easily capture output in this test
	// but we can verify it doesn't error
	err := run(t.Context(), cfg, strings.NewReader(input))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Just verify no panic
	_ = output
}

func TestRunDryRunWithRegistryMirrors(t *testing.T) {
	cfg := &Config{
		DryRun:          true,
		Verbose:         true,
		RegistryMirrors: "docker.io=artifactory.internal.com/docker-remote",
	}

	input := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc123def456789012345678901234567890123456789012345678901234
`

	// run() should succeed with valid registry mirrors
	err := run(t.Context(), cfg, strings.NewReader(input))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunDryRunWithInvalidRegistryMirrors(t *testing.T) {
	cfg := &Config{
		DryRun:          true,
		Verbose:         false,
		RegistryMirrors: "invalid-mirror-format",
	}

	input := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc123def456789012345678901234567890123456789012345678901234
`

	// run() should fail with invalid registry mirrors
	err := run(t.Context(), cfg, strings.NewReader(input))
	if err == nil {
		t.Errorf("expected error for invalid registry mirrors format, got nil")
	}
	if !strings.Contains(err.Error(), "parsing registry mirrors") {
		t.Errorf("expected error message to contain 'parsing registry mirrors', got: %v", err)
	}
}

func TestRunDryRunWithMultipleRegistryMirrors(t *testing.T) {
	cfg := &Config{
		DryRun:          true,
		Verbose:         false,
		RegistryMirrors: "docker.io=artifactory.internal.com/docker-remote,gcr.io=artifactory.internal.com/gcr-remote",
	}

	input := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc123def456789012345678901234567890123456789012345678901234
`

	// run() should succeed with multiple valid registry mirrors
	err := run(t.Context(), cfg, strings.NewReader(input))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
