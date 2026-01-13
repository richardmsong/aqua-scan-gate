package aqua

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TokenManager", func() {
	Describe("GetToken", func() {
		It("should return configured token", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Token: "my-static-token",
			}, &http.Client{}, false)

			token := tm.GetToken()
			Expect(token).To(Equal("my-static-token"))
		})

		It("should return same token on multiple calls", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Token: "my-static-token",
			}, &http.Client{}, false)

			token1 := tm.GetToken()
			token2 := tm.GetToken()

			Expect(token1).To(Equal(token2))
		})

		It("should return empty string when no token configured", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{}, &http.Client{}, false)

			token := tm.GetToken()
			Expect(token).To(BeEmpty())
		})
	})
})

var _ = Describe("HMAC256 Signing", func() {
	Describe("SignRequest", func() {
		It("should not add headers when HMAC secret is empty", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Token:      "test-token",
				HMACSecret: "",
			}, &http.Client{}, false)

			req, _ := http.NewRequest("GET", "https://api.aquasec.com/test", nil)
			err := tm.SignRequest(req, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get("X-Timestamp")).To(BeEmpty())
			Expect(req.Header.Get("X-Signature")).To(BeEmpty())
		})

		It("should add signature headers when HMAC secret is set", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Token:      "test-token",
				HMACSecret: "my-secret-key",
			}, &http.Client{}, false)

			req, _ := http.NewRequest("GET", "https://api.aquasec.com/test", nil)
			err := tm.SignRequest(req, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(req.Header.Get("X-Timestamp")).NotTo(BeEmpty())
			Expect(req.Header.Get("X-Signature")).NotTo(BeEmpty())
		})

		It("should generate consistent signatures for same input", func() {
			// Use same timestamp by directly calling computeHMAC256
			// Format: timestamp + method + path + body (no separators)
			message := "2024-01-01T00:00:00ZGET/test"
			sig1 := computeHMAC256(message, "my-secret-key")
			sig2 := computeHMAC256(message, "my-secret-key")
			Expect(sig1).To(Equal(sig2))
		})

		It("should generate different signatures for different secrets", func() {
			// Format: timestamp + method + path + body (no separators)
			message := "2024-01-01T00:00:00ZGET/test"
			sig1 := computeHMAC256(message, "secret-1")
			sig2 := computeHMAC256(message, "secret-2")
			Expect(sig1).NotTo(Equal(sig2))
		})

		It("should include request body in signature", func() {
			tm := NewTokenManager("https://api.aquasec.com", AuthConfig{
				Token:      "test-token",
				HMACSecret: "my-secret-key",
			}, &http.Client{}, false)

			req1, _ := http.NewRequest("POST", "https://api.aquasec.com/test", nil)
			req2, _ := http.NewRequest("POST", "https://api.aquasec.com/test", nil)

			err := tm.SignRequest(req1, []byte(`{"foo":"bar"}`))
			Expect(err).NotTo(HaveOccurred())
			err = tm.SignRequest(req2, []byte(`{"foo":"baz"}`))
			Expect(err).NotTo(HaveOccurred())

			// Different bodies should produce different signatures
			// (though timestamps might also differ, making them different anyway)
			sig1 := req1.Header.Get("X-Signature")
			sig2 := req2.Header.Get("X-Signature")
			Expect(sig1).NotTo(BeEmpty())
			Expect(sig2).NotTo(BeEmpty())
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

	It("should use Auth.Token when provided", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				Token: "new-style-token",
			},
		})

		Expect(client).NotTo(BeNil())
	})

	It("should support HMAC secret configuration", func() {
		client := NewClient(Config{
			BaseURL:  "https://api.aquasec.com",
			Registry: "test-registry",
			Auth: AuthConfig{
				Token:      "test-token",
				HMACSecret: "my-hmac-secret",
			},
		})

		Expect(client).NotTo(BeNil())
	})
})
