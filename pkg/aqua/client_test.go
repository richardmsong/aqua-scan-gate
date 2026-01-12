package aqua

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
	// Remove digest if present
	originalRef := imageRef
	if strings.Contains(imageRef, "@") {
		parts := strings.Split(imageRef, "@")
		imageRef = parts[0]
	}

	// Handle tag
	tagIdx := strings.LastIndex(imageRef, ":")
	hasPort := false

	// Check if the colon is part of a port number (e.g., registry.io:5000)
	if tagIdx > 0 {
		beforeColon := imageRef[:tagIdx]
		if strings.Contains(beforeColon, "/") {
			// Colon is after a slash, so it's a tag
			tag = imageRef[tagIdx+1:]
			imageRef = imageRef[:tagIdx]
		} else if strings.Contains(beforeColon, ".") {
			// Colon is in the domain, so it's a port
			hasPort = true
			tag = "latest"
		} else {
			// Single name with colon, it's a tag
			tag = imageRef[tagIdx+1:]
			imageRef = imageRef[:tagIdx]
		}
	} else {
		tag = "latest"
	}

	// Handle registry and repository
	var hostname, repository string
	slashIdx := strings.Index(imageRef, "/")
	if slashIdx > 0 {
		registryPart := imageRef[:slashIdx]
		// Check if it looks like a registry (has . or :)
		if strings.Contains(registryPart, ".") || (hasPort && strings.Contains(registryPart, ":")) {
			hostname = registryPart
			repository = imageRef[slashIdx+1:]
		} else {
			// It's a Docker Hub image with namespace (e.g., library/nginx)
			hostname = "docker.io"
			repository = imageRef
		}
	} else {
		// No slash, it's a Docker Hub image
		hostname = "docker.io"
		repository = imageRef
	}

	// Get the Aqua registry name for this hostname
	registryName, err = m.GetRegistryName(ctx, hostname)
	if err != nil {
		return "", "", "", fmt.Errorf("looking up registry name for %s: %w", originalRef, err)
	}

	return registryName, repository, tag, nil
}

func normalizeHostname(hostname string) string {
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	return hostname
}

var _ = Describe("ConvertImageRef", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("Docker Hub images", func() {
		It("should parse image with namespace and tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/python:3.12.12")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/python"))
			Expect(tag).To(Equal("3.12.12"))
		})

		It("should parse image without explicit registry", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "library/nginx:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse single name image", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "nginx")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "nginx:1.21.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("nginx"))
			Expect(tag).To(Equal("1.21.0"))
		})

		It("should parse official image shorthand", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "ubuntu")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("ubuntu"))
			Expect(tag).To(Equal("latest"))
		})
	})

	Describe("Cloud provider registries", func() {
		It("should parse GCR image with tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"gcr.io": "GCR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image:v1.0.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("v1.0.0"))
		})

		It("should parse ECR-style registry", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"123456789012.dkr.ecr.us-east-1.amazonaws.com": "AWS ECR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("AWS ECR"))
			Expect(image).To(Equal("myapp"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse Azure Container Registry", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"myregistry.azurecr.io": "Azure ACR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "myregistry.azurecr.io/samples/nginx:latest")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Azure ACR"))
			Expect(image).To(Equal("samples/nginx"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse Quay.io image", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"quay.io": "Quay",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "quay.io/prometheus/prometheus:v2.30.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Quay"))
			Expect(image).To(Equal("prometheus/prometheus"))
			Expect(tag).To(Equal("v2.30.0"))
		})
	})

	Describe("Custom registries", func() {
		It("should parse registry with port", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"registry.io:5000": "Custom Registry",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io:5000/team/project/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("team/project/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse registry with port and no tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"registry.io:5000": "Custom Registry",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io:5000/image")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("image"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse registry with subdomain", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"eu.gcr.io": "GCR EU",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "eu.gcr.io/project-id/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR EU"))
			Expect(image).To(Equal("project-id/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse registry with hyphen in name", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"my-registry.io": "My Registry",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "my-registry.io/app:v1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("My Registry"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("v1"))
		})
	})

	Describe("Image formats", func() {
		It("should parse image with digest", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/alpine@sha256:abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/alpine"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with tag and digest", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"gcr.io": "GCR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image:v1.0@sha256:abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("v1.0"))
		})

		It("should parse multi-level namespace", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"registry.io": "Custom Registry",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "registry.io/team/project/subproject/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Custom Registry"))
			Expect(image).To(Equal("team/project/subproject/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse image with complex tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/app:v1.2.3-alpha.1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/app"))
			Expect(tag).To(Equal("v1.2.3-alpha.1"))
		})

		It("should default to latest when no tag specified", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"gcr.io": "GCR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/project/image")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("project/image"))
			Expect(tag).To(Equal("latest"))
		})

		It("should parse image with underscores and hyphens", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/my_org/my-app_v2:1.0.0-rc1")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("my_org/my-app_v2"))
			Expect(tag).To(Equal("1.0.0-rc1"))
		})

		It("should parse image with SHA-like tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/library/app:sha-abcd1234")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("library/app"))
			Expect(tag).To(Equal("sha-abcd1234"))
		})
	})

	Describe("Edge cases", func() {
		It("should fail with empty registry cache", func() {
			client := &aquaClient{
				registryCache:        map[string]string{},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			_, _, _, err := client.ConvertImageRef(ctx, "nginx:latest")
			Expect(err).To(HaveOccurred())
		})

		It("should parse image path with many slashes", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"gcr.io": "GCR",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "gcr.io/a/b/c/d/e/image:tag")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("GCR"))
			Expect(image).To(Equal("a/b/c/d/e/image"))
			Expect(tag).To(Equal("tag"))
		})

		It("should parse numeric tag", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/app:12345")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("12345"))
		})

		It("should parse tag with special characters", func() {
			client := &aquaClient{
				registryCache: map[string]string{
					"docker.io": "Docker Hub",
				},
				registryCacheMu:      sync.RWMutex{},
				registryCacheRefresh: time.Now(),
			}

			registry, image, tag, err := client.ConvertImageRef(ctx, "docker.io/app:v1.0_beta-rc.1+build.123")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("Docker Hub"))
			Expect(image).To(Equal("app"))
			Expect(tag).To(Equal("v1.0_beta-rc.1+build.123"))
		})
	})
})
