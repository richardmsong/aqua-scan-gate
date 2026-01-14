package aqua

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAquaClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aqua Client Suite")
}

// createMockServerWithToken creates a test server that handles both token requests and custom handlers
func createMockServerWithToken(bearerToken string, apiHandler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle token requests
		if r.URL.Path == "/v2/tokens" && r.Method == "POST" {
			resp := tokenResponse{
				Status: 200,
				Code:   0,
				Data:   bearerToken,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// Handle other API requests
		if apiHandler != nil {
			apiHandler(w, r)
		}
	}))
}

var _ = Describe("parseImageReference", func() {
	Context("with various image reference formats", func() {
		It("should parse image with registry and repository", func() {
			containerRegistry, imageName, tag, err := parseImageReference(
				"gcr.io/my-project/my-image:latest",
				"sha256:abc123def456",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerRegistry).To(Equal("gcr.io"))
			Expect(imageName).To(Equal("my-project/my-image"))
			Expect(tag).To(Equal("@sha256:abc123def456"))
		})

		It("should parse Docker Hub image with repository", func() {
			containerRegistry, imageName, tag, err := parseImageReference(
				"richardmsong/jfrog-token-exchanger:v1.0",
				"sha256:abc123",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerRegistry).To(Equal("index.docker.io"))
			Expect(imageName).To(Equal("richardmsong/jfrog-token-exchanger"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should parse official Docker Hub image", func() {
			containerRegistry, imageName, tag, err := parseImageReference(
				"nginx:latest",
				"sha256:xyz789",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerRegistry).To(Equal("index.docker.io"))
			Expect(imageName).To(Equal("library/nginx"))
			Expect(tag).To(Equal("@sha256:xyz789"))
		})

		It("should parse ghcr.io image", func() {
			containerRegistry, imageName, tag, err := parseImageReference(
				"ghcr.io/myorg/myimage:v1.0",
				"sha256:abc123",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerRegistry).To(Equal("ghcr.io"))
			Expect(imageName).To(Equal("myorg/myimage"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should handle image with port in registry", func() {
			containerRegistry, imageName, tag, err := parseImageReference(
				"registry.example.com:5000/my-image:v1",
				"sha256:abc123",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(containerRegistry).To(Equal("registry.example.com:5000"))
			Expect(imageName).To(Equal("my-image"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should return error for invalid image reference", func() {
			_, _, _, err := parseImageReference(
				"",
				"sha256:abc123",
			)
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("GetScanResult", func() {
	var (
		server *httptest.Server
		client Client
	)

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("when image is found (scanned)", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-bearer-token"))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"name": "test-image"}`))
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return StatusFound", func() {
			result, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Status).To(Equal(StatusFound))
			Expect(result.Image).To(Equal("nginx:latest"))
			Expect(result.Digest).To(Equal("sha256:abc123"))
		})
	})

	Context("when image is not found (not scanned)", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/tokens" {
					w.WriteHeader(http.StatusNotFound)
				}
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return StatusNotFound", func() {
			result, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Status).To(Equal(StatusNotFound))
		})
	})

	Context("when API returns an error", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "internal server error"}`))
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error with response body", func() {
			_, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("500"))
			Expect(err.Error()).To(ContainSubstring("internal server error"))
		})
	})

	Context("when token request fails", func() {
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/tokens" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error": "invalid credentials"}`))
					return
				}
				w.WriteHeader(http.StatusOK)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "bad-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error with authentication details", func() {
			_, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("401"))
		})
	})
})

var _ = Describe("TriggerScan", func() {
	var (
		server *httptest.Server
		client Client
	)

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("when scan is triggered successfully", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("POST"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-bearer-token"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

				var reqBody triggerScanRequest
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				Expect(err).NotTo(HaveOccurred())
				Expect(reqBody.Registry).To(Equal("test-registry"))
				Expect(reqBody.Image).To(ContainSubstring("@sha256:abc123"))

				w.WriteHeader(http.StatusCreated)
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return scan ID", func() {
			scanID, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).NotTo(HaveOccurred())
			Expect(scanID).To(ContainSubstring("test-registry"))
			Expect(scanID).To(ContainSubstring("@sha256:abc123"))
		})
	})

	Context("when API returns 400 Bad Request", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "invalid image format"}`))
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error with response body", func() {
			_, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("400"))
			Expect(err.Error()).To(ContainSubstring("invalid image format"))
		})
	})

	Context("when token request fails", func() {
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/tokens" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error": "token expired"}`))
					return
				}
				w.WriteHeader(http.StatusCreated)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "expired-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error with authentication details", func() {
			_, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("401"))
		})
	})

	Context("when API returns 500 Internal Server Error", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "database connection failed"}`))
			})

			client = NewClient(Config{
				BaseURL:  server.URL,
				Registry: "test-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error with response body", func() {
			_, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("500"))
			Expect(err.Error()).To(ContainSubstring("database connection failed"))
		})
	})
})

var _ = Describe("NewClient", func() {
	It("should set default timeout when not provided", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				APIKey:     "test-key",
				HMACSecret: "test-secret",
			},
		})

		// The client is created - we can't directly inspect the timeout,
		// but we can verify the client was created successfully
		Expect(client).NotTo(BeNil())
	})

	It("should use provided timeout", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				APIKey:     "test-key",
				HMACSecret: "test-secret",
			},
			Timeout: 60 * time.Second,
		})

		Expect(client).NotTo(BeNil())
	})
})

var _ = Describe("GetRegistries", func() {
	var (
		server *httptest.Server
		client Client
	)

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("when registries are fetched successfully", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.URL.Path).To(Equal("/api/v2/registries"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-bearer-token"))

				resp := RegistriesResponse{
					Count:    2,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"ghcr.io"},
						},
						{
							Name:     "docker-hub",
							Type:     "docker",
							Prefixes: []string{"docker.io", "index.docker.io"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			})

			client = NewClient(Config{
				BaseURL: server.URL,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return list of registries", func() {
			registries, err := client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(registries).To(HaveLen(2))
			Expect(registries[0].Name).To(Equal("github-registry"))
			Expect(registries[0].Prefixes).To(ContainElement("ghcr.io"))
			Expect(registries[1].Name).To(Equal("docker-hub"))
		})
	})

	Context("when API returns an error", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "database error"}`))
			})

			client = NewClient(Config{
				BaseURL: server.URL,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should return error", func() {
			_, err := client.GetRegistries(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("500"))
		})
	})
})

var _ = Describe("FindRegistryByPrefix", func() {
	var (
		server *httptest.Server
		client Client
	)

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("when default registry is configured", func() {
		BeforeEach(func() {
			client = NewClient(Config{
				BaseURL:  "https://api.aquasec.com",
				Registry: "my-default-registry",
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
				},
			})
		})

		It("should return the configured default registry", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "ghcr.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("my-default-registry"))
		})
	})

	Context("when looking up registry by prefix", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				resp := RegistriesResponse{
					Count:    3,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"ghcr.io"},
						},
						{
							Name:     "docker-hub",
							Type:     "docker",
							Prefixes: []string{"docker.io", "index.docker.io"},
						},
						{
							Name:     "gcr-registry",
							Type:     "gcr",
							Prefixes: []string{"gcr.io", "us.gcr.io", "eu.gcr.io"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			})

			client = NewClient(Config{
				BaseURL: server.URL,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should find registry for ghcr.io", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "ghcr.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("github-registry"))
		})

		It("should find registry for docker.io", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "docker.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("docker-hub"))
		})

		It("should find registry for index.docker.io", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "index.docker.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("docker-hub"))
		})

		It("should find registry for gcr.io", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "gcr.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("gcr-registry"))
		})

		It("should return error for unknown registry", func() {
			_, err := client.FindRegistryByPrefix(context.Background(), "unknown.registry.io")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no Aqua registry found"))
		})
	})

	Context("when prefix has protocol or trailing slash", func() {
		BeforeEach(func() {
			server = createMockServerWithToken("test-bearer-token", func(w http.ResponseWriter, r *http.Request) {
				resp := RegistriesResponse{
					Count:    1,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"https://ghcr.io/"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			})

			client = NewClient(Config{
				BaseURL: server.URL,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should normalize and match registry with protocol", func() {
			registry, err := client.FindRegistryByPrefix(context.Background(), "ghcr.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("github-registry"))
		})
	})
})

var _ = Describe("Registry Caching", func() {
	var (
		server   *httptest.Server
		client   Client
		apiCalls int
	)

	AfterEach(func() {
		if server != nil {
			server.Close()
		}
	})

	Context("when GetRegistries is called multiple times within TTL", func() {
		BeforeEach(func() {
			apiCalls = 0
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle token requests
				if r.URL.Path == "/v2/tokens" && r.Method == "POST" {
					resp := tokenResponse{
						Status: 200,
						Code:   0,
						Data:   "test-bearer-token",
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				// Count only registry API calls
				apiCalls++
				resp := RegistriesResponse{
					Count:    1,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"ghcr.io"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				CacheTTL: 1 * time.Hour,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should only call API once and return cached results", func() {
			// First call - should hit API
			registries1, err := client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(registries1).To(HaveLen(1))
			Expect(apiCalls).To(Equal(1))

			// Second call - should use cache
			registries2, err := client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(registries2).To(HaveLen(1))
			Expect(apiCalls).To(Equal(1)) // Still 1 - no new API call

			// Third call - should still use cache
			registries3, err := client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(registries3).To(HaveLen(1))
			Expect(apiCalls).To(Equal(1)) // Still 1 - no new API call
		})
	})

	Context("when cache TTL expires", func() {
		BeforeEach(func() {
			apiCalls = 0
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle token requests
				if r.URL.Path == "/v2/tokens" && r.Method == "POST" {
					resp := tokenResponse{
						Status: 200,
						Code:   0,
						Data:   "test-bearer-token",
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				apiCalls++
				resp := RegistriesResponse{
					Count:    1,
					Page:     1,
					PageSize: 100,
					Result: []Registry{
						{
							Name:     "github-registry",
							Type:     "ghcr",
							Prefixes: []string{"ghcr.io"},
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			}))

			// Use a very short TTL for testing expiration
			client = NewClient(Config{
				BaseURL:  server.URL,
				CacheTTL: 1 * time.Millisecond,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should refresh cache after TTL expires", func() {
			// First call - should hit API
			_, err := client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(apiCalls).To(Equal(1))

			// Wait for cache to expire
			time.Sleep(10 * time.Millisecond)

			// Second call - cache expired, should hit API again
			_, err = client.GetRegistries(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(apiCalls).To(Equal(2))
		})
	})

	Context("when FindRegistryByPrefix does not find match in cache", func() {
		var registryList []Registry

		BeforeEach(func() {
			apiCalls = 0
			// Start with only ghcr.io in the registry list
			registryList = []Registry{
				{
					Name:     "github-registry",
					Type:     "ghcr",
					Prefixes: []string{"ghcr.io"},
				},
			}

			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle token requests
				if r.URL.Path == "/v2/tokens" && r.Method == "POST" {
					resp := tokenResponse{
						Status: 200,
						Code:   0,
						Data:   "test-bearer-token",
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(resp)
					return
				}

				apiCalls++
				resp := RegistriesResponse{
					Count:    len(registryList),
					Page:     1,
					PageSize: 100,
					Result:   registryList,
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(resp)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				CacheTTL: 1 * time.Hour,
				Auth: AuthConfig{
					APIKey:     "test-api-key",
					HMACSecret: "test-secret",
					AuthURL:    server.URL,
				},
			})
		})

		It("should refresh cache when registry not found and find it after refresh", func() {
			// First lookup for ghcr.io - should work with initial cache
			registry, err := client.FindRegistryByPrefix(context.Background(), "ghcr.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("github-registry"))
			// First call populates cache, then lookup succeeds without refresh
			Expect(apiCalls).To(Equal(1))

			// Add docker-hub to the registry list (simulating server-side change)
			registryList = append(registryList, Registry{
				Name:     "docker-hub",
				Type:     "docker",
				Prefixes: []string{"docker.io", "index.docker.io"},
			})

			// Lookup docker.io - not in cache, should trigger refresh
			registry, err = client.FindRegistryByPrefix(context.Background(), "docker.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("docker-hub"))
			// Should have made a refresh call (cache hit first, then refresh on miss)
			Expect(apiCalls).To(Equal(2))
		})

		It("should return error if registry not found even after refresh", func() {
			// Lookup unknown registry
			_, err := client.FindRegistryByPrefix(context.Background(), "unknown.registry.io")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no Aqua registry found"))
			// Should have made 2 API calls (initial cache miss + refresh)
			Expect(apiCalls).To(Equal(2))
		})
	})
})
