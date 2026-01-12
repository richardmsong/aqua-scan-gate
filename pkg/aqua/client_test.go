package aqua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Test fixtures for mocking Aqua API responses

// mockTokenResponse returns a successful token generation response
func mockTokenResponse() string {
	return `{
		"status": 200,
		"code": 0,
		"data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
	}`
}

// mockScanResultResponse returns a successful scan result with vulnerabilities
func mockScanResultResponse() string {
	return `{
		"image_name": "nginx:latest",
		"registry": "Docker Hub",
		"disallowed": false,
		"scan_date": "2024-01-15T10:30:00Z",
		"cves_counts": {
			"total": 10,
			"critical": 0,
			"high": 2,
			"medium": 5,
			"low": 3,
			"score_average": 5.8
		},
		"cves": [
			{
				"imageid": "nginx:latest",
				"file": "libssl1.1_1.1.1-1_amd64.deb",
				"name": "CVE-2023-12345",
				"type": "CVE",
				"description": "Test vulnerability",
				"score": 7.5,
				"severity": "high",
				"publishdate": "2023-01-15",
				"acknowledged": false
			}
		]
	}`
}

// mockScanResultWithCriticalVulns returns scan result with critical vulnerabilities
func mockScanResultWithCriticalVulns() string {
	return `{
		"image_name": "vulnerable:latest",
		"registry": "Docker Hub",
		"disallowed": false,
		"scan_date": "2024-01-16T14:20:00Z",
		"cves_counts": {
			"total": 15,
			"critical": 3,
			"high": 5,
			"medium": 4,
			"low": 3,
			"score_average": 8.2
		}
	}`
}

// mockScanStatusPending returns a pending scan status
func mockScanStatusPending() string {
	return `{"status": "Pending"}`
}

// mockScanStatusInProgress returns an in-progress scan status
func mockScanStatusInProgress() string {
	return `{"status": "In Progress"}`
}

// mockScanStatusScanned returns a completed scan status
func mockScanStatusScanned() string {
	return `{"status": "Scanned"}`
}

// mockScanStatusFailed returns a failed scan status
func mockScanStatusFailed() string {
	return `{"status": "Fail"}`
}

// mockImageIdentifierResponse returns a successful image identifier response
func mockImageIdentifierResponse() string {
	return `{
		"name": "nginx:latest",
		"digest": "sha256:abcdef1234567890",
		"registry": "Docker Hub",
		"repository": "library/nginx",
		"uid": "12345-67890-abcdef"
	}`
}

var _ = Describe("Aqua Client", func() {
	Describe("Client Initialization", func() {
		Context("when creating a new client", func() {
			It("should create a US region client", func() {
				config := Config{
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				}

				client := NewClient(config)
				Expect(client).NotTo(BeNil())

				aquaClient, ok := client.(*aquaClient)
				Expect(ok).To(BeTrue())
				Expect(aquaClient.config.Region).To(Equal("us"))
				Expect(aquaClient.config.Timeout).NotTo(BeZero())
			})

			It("should create a EU region client", func() {
				config := Config{
					Region:    "eu",
					APIKey:    "test-key",
					APISecret: "test-secret",
				}

				client := NewClient(config)
				Expect(client).NotTo(BeNil())

				aquaClient, ok := client.(*aquaClient)
				Expect(ok).To(BeTrue())
				Expect(aquaClient.config.Region).To(Equal("eu"))
			})

			It("should create a client with custom timeout", func() {
				config := Config{
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
					Timeout:   60 * time.Second,
				}

				client := NewClient(config)
				Expect(client).NotTo(BeNil())

				aquaClient, ok := client.(*aquaClient)
				Expect(ok).To(BeTrue())
				Expect(aquaClient.config.Timeout).To(Equal(60 * time.Second))
			})
		})
	})

	Describe("Authentication", func() {
		var server *httptest.Server

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when authenticating with valid credentials", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify authentication headers
					Expect(r.Header.Get("X-API-Key")).NotTo(BeEmpty())
					Expect(r.Header.Get("X-Timestamp")).NotTo(BeEmpty())
					Expect(r.Header.Get("X-Signature")).NotTo(BeEmpty())

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockTokenResponse()))
				}))
			})

			It("should successfully authenticate and set token", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				aquaClient := client.(*aquaClient)
				err := aquaClient.authenticate(context.Background())

				Expect(err).NotTo(HaveOccurred())
				Expect(aquaClient.token).NotTo(BeEmpty())
			})
		})

		Context("when authentication fails", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"status": 401, "message": "Invalid credentials"}`))
				}))
			})

			It("should return an error", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				aquaClient := client.(*aquaClient)
				err := aquaClient.authenticate(context.Background())

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("GetScanResult", func() {
		var server *httptest.Server
		var callCount int

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when retrieving scan results successfully", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					Expect(r.Header.Get("Authorization")).NotTo(BeEmpty())
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanResultResponse()))
				}))
			})

			It("should return scan result with vulnerability counts", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanResult(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusCompleted))
			})
		})

		Context("when retrieving scan result with critical vulnerabilities", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanResultWithCriticalVulns()))
				}))
			})

			It("should return scan result with critical vulnerabilities", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanResult(context.Background(), "Docker Hub", "vulnerable:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusCompleted))
			})
		})

		Context("when image is not found", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusNotFound)
				}))
			})

			It("should return StatusNotFound", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanResult(context.Background(), "Docker Hub", "nonexistent:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusNotFound))
			})
		})

		Context("when server returns an error", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"status": 500, "message": "Internal server error"}`))
				}))
			})

			It("should return an error", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				_, err := client.GetScanResult(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("TriggerScan", func() {
		var server *httptest.Server
		var callCount int

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when triggering a scan successfully", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					Expect(r.Method).To(Equal(http.MethodPost))
					Expect(r.Header.Get("Authorization")).NotTo(BeEmpty())

					w.WriteHeader(http.StatusOK)
				}))
			})

			It("should trigger scan for Docker Hub image", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				err := client.TriggerScan(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
			})

			It("should trigger scan with URL encoding", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				err := client.TriggerScan(context.Background(), "Private Registry", "my-app:v1.0")

				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("when authentication fails during scan trigger", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusUnauthorized)
				}))
			})

			It("should return an error", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				err := client.TriggerScan(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("GetScanStatus", func() {
		var server *httptest.Server
		var callCount int

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when scan is completed", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanStatusScanned()))
				}))
			})

			It("should return StatusCompleted", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusCompleted))
			})
		})

		Context("when scan is pending", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanStatusPending()))
				}))
			})

			It("should return StatusQueued", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusQueued))
			})
		})

		Context("when scan is in progress", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanStatusInProgress()))
				}))
			})

			It("should return StatusScanning", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusScanning))
			})
		})

		Context("when scan failed", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanStatusFailed()))
				}))
			})

			It("should return StatusFailed", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusFailed))
			})
		})

		Context("when image is not found", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusNotFound)
				}))
			})

			It("should return StatusNotFound", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetScanStatus(context.Background(), "Docker Hub", "nonexistent:latest")

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Status).To(Equal(StatusNotFound))
			})
		})
	})

	Describe("Token Management", func() {
		var server *httptest.Server
		var callCount int

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when token expires", func() {
			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockScanStatusScanned()))
				}))
			})

			It("should re-authenticate when token expires", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				aquaClient := client.(*aquaClient)

				// First call - should authenticate
				_, err := client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")
				Expect(err).NotTo(HaveOccurred())

				// Expire the token
				aquaClient.tokenExpiry = time.Now().Add(-1 * time.Minute)

				// Second call - should re-authenticate
				_, err = client.GetScanStatus(context.Background(), "Docker Hub", "nginx:latest")
				Expect(err).NotTo(HaveOccurred())

				// Should have multiple calls (including auth)
				Expect(callCount).To(BeNumerically(">", 2))
			})
		})
	})

	Describe("Error Handling", func() {
		var server *httptest.Server

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		Context("when context is cancelled", func() {
			BeforeEach(func() {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate slow response
					time.Sleep(100 * time.Millisecond)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockTokenResponse()))
				}))
			})

			It("should return context cancellation error", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
					Timeout:   50 * time.Millisecond,
				})

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()

				_, err := client.GetScanStatus(ctx, "Docker Hub", "nginx:latest")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when receiving invalid JSON response", func() {
			var callCount int

			BeforeEach(func() {
				callCount = 0
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					callCount++

					if callCount == 1 {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid json"))
				}))
			})

			It("should return JSON decode error", func() {
				client := NewClient(Config{
					BaseURL:   server.URL,
					Region:    "us",
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				_, err := client.GetScanResult(context.Background(), "Docker Hub", "nginx:latest")
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("Image Reference Parsing", func() {
		type parseTestCase struct {
			imageRef         string
			expectedRegistry string
			expectedRepo     string
			expectedTag      string
		}

		DescribeTable("parsing different image references",
			func(tc parseTestCase) {
				registry, repo, tag, err := parseImageReference(tc.imageRef)

				Expect(err).NotTo(HaveOccurred())
				Expect(registry).To(Equal(tc.expectedRegistry))
				Expect(repo).To(Equal(tc.expectedRepo))
				Expect(tag).To(Equal(tc.expectedTag))
			},
			Entry("Docker Hub image with tag", parseTestCase{
				imageRef:         "nginx:latest",
				expectedRegistry: "Docker Hub",
				expectedRepo:     "nginx",
				expectedTag:      "latest",
			}),
			Entry("Docker Hub image without tag", parseTestCase{
				imageRef:         "nginx",
				expectedRegistry: "Docker Hub",
				expectedRepo:     "nginx",
				expectedTag:      "latest",
			}),
			Entry("Private registry with port", parseTestCase{
				imageRef:         "registry.io:5000/myapp:v1.0",
				expectedRegistry: "registry.io:5000",
				expectedRepo:     "myapp",
				expectedTag:      "v1.0",
			}),
			Entry("GCR image", parseTestCase{
				imageRef:         "gcr.io/project/image:tag",
				expectedRegistry: "gcr.io",
				expectedRepo:     "project/image",
				expectedTag:      "tag",
			}),
		)
	})

	Describe("GetImageByDigest", func() {
		Context("when querying by config digest", func() {
			It("should return image identifier when digest exists", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					if r.URL.Path == "/api/v1/images/details/sha256:abcdef1234567890" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockImageIdentifierResponse()))
						return
					}

					w.WriteHeader(http.StatusNotFound)
				}))
				defer server.Close()

				client := NewClient(Config{
					BaseURL:   server.URL,
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetImageByDigest(context.Background(), "sha256:abcdef1234567890")
				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Name).To(Equal("nginx:latest"))
				Expect(result.Digest).To(Equal("sha256:abcdef1234567890"))
				Expect(result.Registry).To(Equal("Docker Hub"))
				Expect(result.Repository).To(Equal("library/nginx"))
			})

			It("should return nil when digest not found", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusNotFound)
				}))
				defer server.Close()

				client := NewClient(Config{
					BaseURL:   server.URL,
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetImageByDigest(context.Background(), "sha256:nonexistent")
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should handle digest with special characters", func() {
				var requestPath string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					// Capture the request path for verification
					requestPath = r.URL.Path
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(mockImageIdentifierResponse()))
				}))
				defer server.Close()

				client := NewClient(Config{
					BaseURL:   server.URL,
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				_, err := client.GetImageByDigest(context.Background(), "sha256:abc123")
				Expect(err).NotTo(HaveOccurred())
				Expect(requestPath).To(Equal("/api/v1/images/details/sha256:abc123"))
			})

			It("should handle API errors", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error": "Internal server error"}`))
				}))
				defer server.Close()

				client := NewClient(Config{
					BaseURL:   server.URL,
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetImageByDigest(context.Background(), "sha256:test")
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("unexpected status code 500"))
			})

			It("should handle malformed JSON response", func() {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v2/tokens" {
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write([]byte(mockTokenResponse()))
						return
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{invalid json`))
				}))
				defer server.Close()

				client := NewClient(Config{
					BaseURL:   server.URL,
					APIKey:    "test-key",
					APISecret: "test-secret",
				})

				result, err := client.GetImageByDigest(context.Background(), "sha256:test")
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
				Expect(err.Error()).To(ContainSubstring("decoding response"))
			})
		})
	})
})
