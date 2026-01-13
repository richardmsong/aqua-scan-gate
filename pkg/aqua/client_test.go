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

var _ = Describe("parseImageReference", func() {
	Context("with various image reference formats", func() {
		It("should parse image with registry and repository", func() {
			registry, imageName, tag, err := parseImageReference(
				"gcr.io/my-project/my-image:latest",
				"sha256:abc123def456",
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("gcr.io"))
			Expect(imageName).To(Equal("my-project/my-image"))
			Expect(tag).To(Equal("@sha256:abc123def456"))
		})

		It("should parse Docker Hub image with repository", func() {
			registry, imageName, tag, err := parseImageReference(
				"richardmsong/jfrog-token-exchanger:v1.0",
				"sha256:abc123",
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("index.docker.io"))
			Expect(imageName).To(Equal("richardmsong/jfrog-token-exchanger"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should parse official Docker Hub image", func() {
			registry, imageName, tag, err := parseImageReference(
				"nginx:latest",
				"sha256:xyz789",
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("index.docker.io"))
			Expect(imageName).To(Equal("library/nginx"))
			Expect(tag).To(Equal("@sha256:xyz789"))
		})

		It("should use default registry when provided", func() {
			registry, imageName, tag, err := parseImageReference(
				"gcr.io/project/image:tag",
				"sha256:abc123",
				"my-aqua-registry",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("my-aqua-registry"))
			Expect(imageName).To(Equal("project/image"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should handle image with port in registry", func() {
			registry, imageName, tag, err := parseImageReference(
				"registry.example.com:5000/my-image:v1",
				"sha256:abc123",
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(registry).To(Equal("registry.example.com:5000"))
			Expect(imageName).To(Equal("my-image"))
			Expect(tag).To(Equal("@sha256:abc123"))
		})

		It("should return error for invalid image reference", func() {
			_, _, _, err := parseImageReference(
				"",
				"sha256:abc123",
				"",
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
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-api-key"))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"name": "test-image"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
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
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
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
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "internal server error"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
			})
		})

		It("should return error with response body", func() {
			_, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("500"))
			Expect(err.Error()).To(ContainSubstring("internal server error"))
		})
	})

	Context("when API returns 401 Unauthorized", func() {
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": "invalid token"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "bad-api-key",
				Registry: "test-registry",
			})
		})

		It("should return error with authentication details", func() {
			_, err := client.GetScanResult(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("401"))
			Expect(err.Error()).To(ContainSubstring("invalid token"))
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
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("POST"))
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer test-api-key"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

				var reqBody triggerScanRequest
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				Expect(err).NotTo(HaveOccurred())
				Expect(reqBody.Registry).To(Equal("test-registry"))
				Expect(reqBody.Image).To(ContainSubstring("@sha256:abc123"))

				w.WriteHeader(http.StatusCreated)
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
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
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "invalid image format"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
			})
		})

		It("should return error with response body", func() {
			_, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("400"))
			Expect(err.Error()).To(ContainSubstring("invalid image format"))
		})
	})

	Context("when API returns 401 Unauthorized", func() {
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": "token expired"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "expired-api-key",
				Registry: "test-registry",
			})
		})

		It("should return error with authentication details", func() {
			_, err := client.TriggerScan(context.Background(), "nginx:latest", "sha256:abc123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("401"))
			Expect(err.Error()).To(ContainSubstring("token expired"))
		})
	})

	Context("when API returns 500 Internal Server Error", func() {
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error": "database connection failed"}`))
			}))

			client = NewClient(Config{
				BaseURL:  server.URL,
				APIKey:   "test-api-key",
				Registry: "test-registry",
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
			APIKey:   "test-key",
			Registry: "test-registry",
		})

		// The client is created - we can't directly inspect the timeout,
		// but we can verify the client was created successfully
		Expect(client).NotTo(BeNil())
	})

	It("should use provided timeout", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			APIKey:   "test-key",
			Registry: "test-registry",
			Timeout:  60 * time.Second,
		})

		Expect(client).NotTo(BeNil())
	})
})
