package aqua

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TokenManager", func() {
	Describe("GetToken", func() {
		It("should fetch token from Aqua API", func() {
			// Set up mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				Expect(r.Method).To(Equal("POST"))
				Expect(r.URL.Path).To(Equal("/v2/tokens"))
				Expect(r.Header.Get("X-API-Key")).To(Equal("my-api-key"))
				Expect(r.Header.Get("X-Timestamp")).NotTo(BeEmpty())
				Expect(r.Header.Get("X-Signature")).NotTo(BeEmpty())
				Expect(r.Header.Get("Content-Type")).To(Equal("application/json"))

				// Return mock token
				resp := tokenResponse{
					Status: 200,
					Code:   0,
					Data:   "mock-bearer-token-12345",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			tm := NewTokenManager(server.URL, AuthConfig{
				APIKey:     "my-api-key",
				HMACSecret: "my-secret",
			}, &http.Client{}, false)

			token, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(token).To(Equal("mock-bearer-token-12345"))
		})

		It("should cache token and reuse it", func() {
			var requestCount int32

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&requestCount, 1)
				resp := tokenResponse{
					Status: 200,
					Code:   0,
					Data:   "cached-token",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			tm := NewTokenManager(server.URL, AuthConfig{
				APIKey:     "my-api-key",
				HMACSecret: "my-secret",
			}, &http.Client{}, false)

			// First call
			token1, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(token1).To(Equal("cached-token"))

			// Second call should use cache
			token2, err := tm.GetToken(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(token2).To(Equal("cached-token"))

			// Should only have made one request
			Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(1)))
		})

		It("should handle concurrent token requests", func() {
			var requestCount int32

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&requestCount, 1)
				// Add slight delay to simulate network
				time.Sleep(10 * time.Millisecond)
				resp := tokenResponse{
					Status: 200,
					Code:   0,
					Data:   "concurrent-token",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			tm := NewTokenManager(server.URL, AuthConfig{
				APIKey:     "my-api-key",
				HMACSecret: "my-secret",
			}, &http.Client{}, false)

			// Make concurrent requests
			var wg sync.WaitGroup
			tokens := make([]string, 10)
			errors := make([]error, 10)

			for i := 0; i < 10; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					tokens[idx], errors[idx] = tm.GetToken(context.Background())
				}(i)
			}

			wg.Wait()

			// All should have succeeded with the same token
			for i := 0; i < 10; i++ {
				Expect(errors[i]).NotTo(HaveOccurred())
				Expect(tokens[i]).To(Equal("concurrent-token"))
			}

			// Should only have made one request due to locking
			Expect(atomic.LoadInt32(&requestCount)).To(Equal(int32(1)))
		})

		It("should return error when API returns non-200", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("invalid credentials"))
			}))
			defer server.Close()

			tm := NewTokenManager(server.URL, AuthConfig{
				APIKey:     "bad-key",
				HMACSecret: "my-secret",
			}, &http.Client{}, false)

			_, err := tm.GetToken(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("token request failed with status 401"))
		})

		It("should return error when response has empty token", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := tokenResponse{
					Status: 200,
					Code:   0,
					Data:   "",
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			tm := NewTokenManager(server.URL, AuthConfig{
				APIKey:     "my-api-key",
				HMACSecret: "my-secret",
			}, &http.Client{}, false)

			_, err := tm.GetToken(context.Background())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty token"))
		})
	})
})

var _ = Describe("HMAC256 Signing", func() {
	Describe("computeHMAC256", func() {
		It("should generate consistent signatures for same input", func() {
			message := "1234567890POSTv2/tokens{\"validity\":240}"
			sig1 := computeHMAC256(message, "my-secret-key")
			sig2 := computeHMAC256(message, "my-secret-key")
			Expect(sig1).To(Equal(sig2))
		})

		It("should generate different signatures for different secrets", func() {
			message := "1234567890POSTv2/tokens{\"validity\":240}"
			sig1 := computeHMAC256(message, "secret-1")
			sig2 := computeHMAC256(message, "secret-2")
			Expect(sig1).NotTo(Equal(sig2))
		})

		It("should generate different signatures for different messages", func() {
			sig1 := computeHMAC256("message1", "my-secret")
			sig2 := computeHMAC256("message2", "my-secret")
			Expect(sig1).NotTo(Equal(sig2))
		})
	})

	Describe("ValidateHMACSignature", func() {
		It("should return true for valid signature", func() {
			message := "test message"
			secret := "my-secret"
			signature := computeHMAC256(message, secret)

			valid := ValidateHMACSignature(message, signature, secret)
			Expect(valid).To(BeTrue())
		})

		It("should return false for invalid signature", func() {
			message := "test message"

			valid := ValidateHMACSignature(message, "invalid-signature", "my-secret")
			Expect(valid).To(BeFalse())
		})

		It("should return false for wrong secret", func() {
			message := "test message"
			signature := computeHMAC256(message, "correct-secret")

			valid := ValidateHMACSignature(message, signature, "wrong-secret")
			Expect(valid).To(BeFalse())
		})
	})
})

var _ = Describe("NewClient with Auth", func() {
	It("should maintain backward compatibility with APIKey", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			APIKey:   "legacy-api-key",
			Registry: "test-registry",
		})

		Expect(client).NotTo(BeNil())
		// The client should work with the legacy APIKey
	})

	It("should use Auth.APIKey when provided", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				APIKey:     "new-style-api-key",
				HMACSecret: "my-hmac-secret",
			},
		})

		Expect(client).NotTo(BeNil())
	})

	It("should support HMAC secret configuration", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				APIKey:     "test-api-key",
				HMACSecret: "my-hmac-secret",
			},
		})

		Expect(client).NotTo(BeNil())
	})
})

var _ = Describe("TokenManager with AuthURL", func() {
	It("should use AuthURL for token requests when provided", func() {
		// Set up mock auth server (simulating regional endpoint)
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).To(Equal("POST"))
			Expect(r.URL.Path).To(Equal("/v2/tokens"))

			resp := tokenResponse{
				Status: 200,
				Code:   0,
				Data:   "token-from-auth-server",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer authServer.Close()

		// Use a different baseURL to verify it's not being used for auth
		tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
			APIKey:     "my-api-key",
			HMACSecret: "my-secret",
			AuthURL:    authServer.URL, // This should be used
		}, &http.Client{}, false)

		token, err := tm.GetToken(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("token-from-auth-server"))
	})

	It("should fall back to baseURL when AuthURL is not provided", func() {
		// Set up mock server acting as baseURL
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).To(Equal("POST"))
			Expect(r.URL.Path).To(Equal("/v2/tokens"))

			resp := tokenResponse{
				Status: 200,
				Code:   0,
				Data:   "token-from-base-url",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		// No AuthURL provided, should use baseURL
		tm := NewTokenManager(server.URL, AuthConfig{
			APIKey:     "my-api-key",
			HMACSecret: "my-secret",
			// AuthURL not set
		}, &http.Client{}, false)

		token, err := tm.GetToken(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(token).To(Equal("token-from-base-url"))
	})
})
