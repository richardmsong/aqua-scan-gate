package imageref

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestExtractFromPodSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     *corev1.PodSpec
		expected []ImageRef
	}{
		{
			name: "single container",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:latest"},
				},
			},
			expected: []ImageRef{
				{Image: "nginx:latest", Digest: ""},
			},
		},
		{
			name: "multiple containers",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:latest"},
					{Name: "sidecar", Image: "redis:6"},
				},
			},
			expected: []ImageRef{
				{Image: "nginx:latest", Digest: ""},
				{Image: "redis:6", Digest: ""},
			},
		},
		{
			name: "init containers",
			spec: &corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "init", Image: "busybox:1.35"},
				},
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:latest"},
				},
			},
			expected: []ImageRef{
				{Image: "busybox:1.35", Digest: ""},
				{Image: "nginx:latest", Digest: ""},
			},
		},
		{
			name: "image with digest",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx@sha256:abc123def456"},
				},
			},
			expected: []ImageRef{
				{Image: "nginx@sha256:abc123def456", Digest: "sha256:abc123def456"},
			},
		},
		{
			name: "duplicate images",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app1", Image: "nginx:latest"},
					{Name: "app2", Image: "nginx:latest"},
				},
			},
			expected: []ImageRef{
				{Image: "nginx:latest", Digest: ""},
			},
		},
		{
			name: "ephemeral containers",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: "nginx:latest"},
				},
				EphemeralContainers: []corev1.EphemeralContainer{
					{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox:latest"}},
				},
			},
			expected: []ImageRef{
				{Image: "nginx:latest", Digest: ""},
				{Image: "busybox:latest", Digest: ""},
			},
		},
		{
			name:     "empty spec",
			spec:     &corev1.PodSpec{},
			expected: nil,
		},
		{
			name: "empty image",
			spec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "app", Image: ""},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractFromPodSpec(tt.spec)

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d images, got %d", len(tt.expected), len(result))
				return
			}

			for i, exp := range tt.expected {
				if result[i].Image != exp.Image {
					t.Errorf("expected image %q, got %q", exp.Image, result[i].Image)
				}
				if result[i].Digest != exp.Digest {
					t.Errorf("expected digest %q, got %q", exp.Digest, result[i].Digest)
				}
			}
		})
	}
}

func TestScanName(t *testing.T) {
	tests := []struct {
		name     string
		img      ImageRef
		expected string
	}{
		{
			name:     "image without digest",
			img:      ImageRef{Image: "nginx:latest"},
			expected: "img-", // Will be followed by hash
		},
		{
			name:     "image with digest",
			img:      ImageRef{Image: "nginx@sha256:abc123", Digest: "sha256:abc123def456789012345678901234567890123456789012345678901234"},
			expected: "sha256-abc123def45678901234567890123456789012345678901234567890", // truncated to 63 chars
		},
		{
			name:     "digest truncated at 63 chars",
			img:      ImageRef{Image: "nginx@sha256:abc", Digest: "sha256:abc123def456789012345678901234567890123456789012345678901234567890"},
			expected: "sha256-abc123def45678901234567890123456789012345678901234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ScanName(tt.img)

			// For images without digest, just check prefix
			if tt.img.Digest == "" {
				if len(result) < 4 || result[:4] != "img-" {
					t.Errorf("expected scan name to start with 'img-', got %q", result)
				}
				return
			}

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestHashString(t *testing.T) {
	tests := []struct {
		input    string
		expected int // Expected length of hash
	}{
		{input: "nginx:latest", expected: 64},
		{input: "", expected: 64},
		{input: "a", expected: 64},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := HashString(tt.input)

			if len(result) != tt.expected {
				t.Errorf("expected hash length %d, got %d", tt.expected, len(result))
			}
		})
	}

	// Test determinism
	t.Run("deterministic", func(t *testing.T) {
		hash1 := HashString("nginx:latest")
		hash2 := HashString("nginx:latest")

		if hash1 != hash2 {
			t.Errorf("hash should be deterministic, got %q and %q", hash1, hash2)
		}
	})

	// Test uniqueness
	t.Run("unique", func(t *testing.T) {
		hash1 := HashString("nginx:latest")
		hash2 := HashString("nginx:1.19")

		if hash1 == hash2 {
			t.Errorf("different inputs should produce different hashes")
		}
	})
}

func TestExtractFromPod(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:latest"},
			},
		},
	}

	result := ExtractFromPod(pod)

	if len(result) != 1 {
		t.Errorf("expected 1 image, got %d", len(result))
		return
	}

	if result[0].Image != "nginx:latest" {
		t.Errorf("expected image nginx:latest, got %q", result[0].Image)
	}
}
