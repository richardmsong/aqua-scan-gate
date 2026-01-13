package aqua

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Token is the API token for authentication
	Token string

	// HMACSecret is used for HMAC256 request signing (optional)
	HMACSecret string
}

// TokenManager handles token and request signing
type TokenManager struct {
	config AuthConfig
}

// NewTokenManager creates a new token manager
func NewTokenManager(baseURL string, config AuthConfig, httpClient *http.Client) *TokenManager {
	return &TokenManager{
		config: config,
	}
}

// GetToken returns the configured token
func (tm *TokenManager) GetToken() string {
	return tm.config.Token
}

// SignRequest adds HMAC256 signature to a request
// The signature is computed over: HTTP_METHOD + URL + TIMESTAMP + REQUEST_BODY
func (tm *TokenManager) SignRequest(req *http.Request, body []byte) error {
	if tm.config.HMACSecret == "" {
		return nil // No signing configured
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Build the string to sign
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		req.Method,
		req.URL.String(),
		timestamp,
		string(body),
	)

	// Compute HMAC256 signature
	signature := computeHMAC256(stringToSign, tm.config.HMACSecret)

	// Add signature headers
	req.Header.Set("X-Aqua-Timestamp", timestamp)
	req.Header.Set("X-Aqua-Signature", signature)

	return nil
}

// computeHMAC256 computes HMAC-SHA256 signature
func computeHMAC256(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateHMACSignature validates an incoming HMAC signature
// This can be useful for webhook validation
func ValidateHMACSignature(message, signature, secret string) bool {
	expectedSig := computeHMAC256(message, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}
