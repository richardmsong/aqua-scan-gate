package aqua

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockAquaClient is a test implementation of the aquaClient for testing ConvertImageRef
type mockAquaClient struct {
	registryCache        map[string]string
	registryCacheMu      sync.RWMutex
	registryCacheRefresh time.Time
	refreshCalled        bool
}

func (m *mockAquaClient) GetRegistryName(ctx context.Context, hostname string) (string, error) {
	// Normalize hostname
	hostname = normalizeHostname(hostname)

	m.registryCacheMu.RLock()
	registryName, found := m.registryCache[hostname]
	m.registryCacheMu.RUnlock()

	if !found {
		return "", fmt.Errorf("registry not found in Aqua: %s", hostname)
	}

	return registryName, nil
}

func (m *mockAquaClient) ConvertImageRef(ctx context.Context, imageRef string) (registryName string, imageName string, tag string, err error) {
	// Use the actual implementation logic from aquaClient
	client := &aquaClient{
		registryCache:        m.registryCache,
		registryCacheMu:      m.registryCacheMu,
		registryCacheRefresh: m.registryCacheRefresh,
	}
	return client.ConvertImageRef(ctx, imageRef)
}

func normalizeHostname(hostname string) string {
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	return hostname
}

func TestConvertImageRef(t *testing.T) {
	tests := []struct {
		name            string
		imageRef        string
		registryCache   map[string]string
		wantRegistry    string
		wantImage       string
		wantTag         string
		wantErr         bool
		errContains     string
	}{
		{
			name:     "Docker Hub image with namespace and tag",
			imageRef: "docker.io/library/python:3.12.12",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "library/python",
			wantTag:      "3.12.12",
			wantErr:      false,
		},
		{
			name:     "Docker Hub image without explicit registry",
			imageRef: "library/nginx:latest",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "library/nginx",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Docker Hub single name image",
			imageRef: "nginx",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "nginx",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Docker Hub image with tag",
			imageRef: "nginx:1.21.0",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "nginx",
			wantTag:      "1.21.0",
			wantErr:      false,
		},
		{
			name:     "GCR image with tag",
			imageRef: "gcr.io/project/image:v1.0.0",
			registryCache: map[string]string{
				"gcr.io": "GCR",
			},
			wantRegistry: "GCR",
			wantImage:    "project/image",
			wantTag:      "v1.0.0",
			wantErr:      false,
		},
		{
			name:     "Custom registry with port",
			imageRef: "registry.io:5000/team/project/image:tag",
			registryCache: map[string]string{
				"registry.io:5000": "Custom Registry",
			},
			wantRegistry: "Custom Registry",
			wantImage:    "team/project/image",
			wantTag:      "tag",
			wantErr:      false,
		},
		{
			name:     "Custom registry with port and no tag",
			imageRef: "registry.io:5000/image",
			registryCache: map[string]string{
				"registry.io:5000": "Custom Registry",
			},
			wantRegistry: "Custom Registry",
			wantImage:    "image",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Image with digest",
			imageRef: "docker.io/library/alpine@sha256:abcd1234",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "library/alpine",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Image with tag and digest",
			imageRef: "gcr.io/project/image:v1.0@sha256:abcd1234",
			registryCache: map[string]string{
				"gcr.io": "GCR",
			},
			wantRegistry: "GCR",
			wantImage:    "project/image",
			wantTag:      "v1.0",
			wantErr:      false,
		},
		{
			name:     "Multi-level namespace",
			imageRef: "registry.io/team/project/subproject/image:tag",
			registryCache: map[string]string{
				"registry.io": "Custom Registry",
			},
			wantRegistry: "Custom Registry",
			wantImage:    "team/project/subproject/image",
			wantTag:      "tag",
			wantErr:      false,
		},
		{
			name:     "Image with complex tag",
			imageRef: "docker.io/library/app:v1.2.3-alpha.1",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "library/app",
			wantTag:      "v1.2.3-alpha.1",
			wantErr:      false,
		},
		{
			name:     "ECR-style registry",
			imageRef: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest",
			registryCache: map[string]string{
				"123456789012.dkr.ecr.us-east-1.amazonaws.com": "AWS ECR",
			},
			wantRegistry: "AWS ECR",
			wantImage:    "myapp",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Azure Container Registry",
			imageRef: "myregistry.azurecr.io/samples/nginx:latest",
			registryCache: map[string]string{
				"myregistry.azurecr.io": "Azure ACR",
			},
			wantRegistry: "Azure ACR",
			wantImage:    "samples/nginx",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Image with no tag defaults to latest",
			imageRef: "gcr.io/project/image",
			registryCache: map[string]string{
				"gcr.io": "GCR",
			},
			wantRegistry: "GCR",
			wantImage:    "project/image",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Docker Hub official image shorthand",
			imageRef: "ubuntu",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "ubuntu",
			wantTag:      "latest",
			wantErr:      false,
		},
		{
			name:     "Quay.io image",
			imageRef: "quay.io/prometheus/prometheus:v2.30.0",
			registryCache: map[string]string{
				"quay.io": "Quay",
			},
			wantRegistry: "Quay",
			wantImage:    "prometheus/prometheus",
			wantTag:      "v2.30.0",
			wantErr:      false,
		},
		{
			name:     "Image with underscores and hyphens",
			imageRef: "docker.io/my_org/my-app_v2:1.0.0-rc1",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "my_org/my-app_v2",
			wantTag:      "1.0.0-rc1",
			wantErr:      false,
		},
		{
			name:     "Registry with subdomain",
			imageRef: "eu.gcr.io/project-id/image:tag",
			registryCache: map[string]string{
				"eu.gcr.io": "GCR EU",
			},
			wantRegistry: "GCR EU",
			wantImage:    "project-id/image",
			wantTag:      "tag",
			wantErr:      false,
		},
		{
			name:     "Image with SHA-like tag",
			imageRef: "docker.io/library/app:sha-abcd1234",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "library/app",
			wantTag:      "sha-abcd1234",
			wantErr:      false,
		},
		{
			name:     "Registry with hyphen in name",
			imageRef: "my-registry.io/app:v1",
			registryCache: map[string]string{
				"my-registry.io": "My Registry",
			},
			wantRegistry: "My Registry",
			wantImage:    "app",
			wantTag:      "v1",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &aquaClient{
				registryCache:        tt.registryCache,
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			ctx := context.Background()
			gotRegistry, gotImage, gotTag, err := client.ConvertImageRef(ctx, tt.imageRef)

			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertImageRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ConvertImageRef() error = %v, should contain %q", err, tt.errContains)
				}
				return
			}

			if gotRegistry != tt.wantRegistry {
				t.Errorf("ConvertImageRef() gotRegistry = %v, want %v", gotRegistry, tt.wantRegistry)
			}
			if gotImage != tt.wantImage {
				t.Errorf("ConvertImageRef() gotImage = %v, want %v", gotImage, tt.wantImage)
			}
			if gotTag != tt.wantTag {
				t.Errorf("ConvertImageRef() gotTag = %v, want %v", gotTag, tt.wantTag)
			}
		})
	}
}

// TestConvertImageRef_EdgeCases tests additional edge cases and boundary conditions
func TestConvertImageRef_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		imageRef      string
		registryCache map[string]string
		wantRegistry  string
		wantImage     string
		wantTag       string
		wantErr       bool
	}{
		{
			name:     "Empty registry cache",
			imageRef: "nginx:latest",
			registryCache: map[string]string{},
			wantErr:  true,
		},
		{
			name:     "Image path with many slashes",
			imageRef: "gcr.io/a/b/c/d/e/image:tag",
			registryCache: map[string]string{
				"gcr.io": "GCR",
			},
			wantRegistry: "GCR",
			wantImage:    "a/b/c/d/e/image",
			wantTag:      "tag",
			wantErr:      false,
		},
		{
			name:     "Numeric tag",
			imageRef: "docker.io/app:12345",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "app",
			wantTag:      "12345",
			wantErr:      false,
		},
		{
			name:     "Tag with special characters",
			imageRef: "docker.io/app:v1.0_beta-rc.1+build.123",
			registryCache: map[string]string{
				"docker.io": "Docker Hub",
			},
			wantRegistry: "Docker Hub",
			wantImage:    "app",
			wantTag:      "v1.0_beta-rc.1+build.123",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &aquaClient{
				registryCache:        tt.registryCache,
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			ctx := context.Background()
			gotRegistry, gotImage, gotTag, err := client.ConvertImageRef(ctx, tt.imageRef)

			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertImageRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if gotRegistry != tt.wantRegistry {
				t.Errorf("ConvertImageRef() gotRegistry = %v, want %v", gotRegistry, tt.wantRegistry)
			}
			if gotImage != tt.wantImage {
				t.Errorf("ConvertImageRef() gotImage = %v, want %v", gotImage, tt.wantImage)
			}
			if gotTag != tt.wantTag {
				t.Errorf("ConvertImageRef() gotTag = %v, want %v", gotTag, tt.wantTag)
			}
		})
	}
}
